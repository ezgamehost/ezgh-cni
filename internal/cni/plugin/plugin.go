// Package plugin is the ezgh-vpc-cni CNI plugin containerd runs (CNI 0.4.0 and 1.0.0: ADD, DEL,
// CHECK, VERSION). It asks ipamd for a pod's addresses before it creates anything, then wires a
// routed veth (DP4, DP12): pod eth0 holds an IPv4 /32 with `default via 169.254.1.1` (a permanent
// neighbour to the host veth's MAC) and an IPv6 /128 with `default via fe80::1`; the host routes
// each address to the veth in main and adds `to <addr> lookup main` at pref 512. stdout is the CNI
// result only.
package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/ezgamehost/ezgh-cni/internal/cni/ipamd"
)

const (
	// PodRulePref is each pod address's `to <addr> lookup main`.
	PodRulePref = 512
	Gateway4    = "169.254.1.1"
	Gateway6    = "fe80::1"
)

// NetConf is the conflist's plugin entry.
type NetConf struct {
	types.PluginConf
	Socket string `json:"socket"`
}

// Main runs the plugin (CNI_COMMAND is set).
func Main() {
	skel.PluginMainFuncs(skel.CNIFuncs{Add: cmdAdd, Del: cmdDel, Check: cmdCheck}, version.PluginSupports("0.4.0", "1.0.0"), "ezgh-vpc-cni")
}

// VethName is the pod's host veth: ezp + the first 12 hex digits of SHA-256(containerId + ifName).
func VethName(containerID, ifName string) string {
	sum := sha256.Sum256([]byte(containerID + ifName))
	return "ezp" + hex.EncodeToString(sum[:6])
}

// HostMAC is the host veth's MAC, set at creation (udev's MACAddressPolicy=persistent rewrites a
// random one later, stranding the pod's permanent neighbour): locally administered,
// 0e + the next five bytes of the same SHA-256.
func HostMAC(containerID, ifName string) net.HardwareAddr {
	sum := sha256.Sum256([]byte(containerID + ifName))
	return append(net.HardwareAddr{0x0e}, sum[6:11]...)
}

func parse(args *skel.CmdArgs) (*NetConf, error) {
	var c NetConf
	if err := json.Unmarshal(args.StdinData, &c); err != nil {
		return nil, fmt.Errorf("ezgh-vpc-cni: config: %w", err)
	}
	if c.Socket == "" {
		c.Socket = "/run/ezgh-vpc-cni/ipamd.sock"
	}
	if c.RawPrevResult != nil {
		if err := version.ParsePrevResult(&c.PluginConf); err != nil {
			return nil, fmt.Errorf("ezgh-vpc-cni: prevResult: %w", err)
		}
	}
	return &c, nil
}

// podArgs are kubelet's CNI_ARGS.
type podArgs struct {
	types.CommonArgs
	K8S_POD_NAMESPACE types.UnmarshallableString //nolint:revive // CNI_ARGS names
	K8S_POD_NAME      types.UnmarshallableString //nolint:revive
}

func cmdAdd(args *skel.CmdArgs) error {
	c, err := parse(args)
	if err != nil {
		return err
	}
	r, err := Add(c, args)
	if err != nil {
		return err
	}
	return types.PrintResult(r, c.CNIVersion)
}

// Add asks ipamd, then wires the pod; on a wiring failure it removes what it made.
func Add(c *NetConf, args *skel.CmdArgs) (*current.Result, error) {
	var pa podArgs
	pa.IgnoreUnknown = true
	if err := types.LoadArgs(args.Args, &pa); err != nil {
		return nil, fmt.Errorf("ezgh-vpc-cni: CNI_ARGS: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	a, err := ipamd.Client{Socket: c.Socket}.Add(ctx, ipamd.AddRequest{ContainerID: args.ContainerID, IfName: args.IfName, Netns: args.Netns,
		Namespace: string(pa.K8S_POD_NAMESPACE), Pod: string(pa.K8S_POD_NAME)})
	if err != nil {
		return nil, err
	}
	podMAC, err := Wire(args.Netns, args.ContainerID, args.IfName, a)
	if err != nil {
		_ = Unwire(args.ContainerID, args.IfName, []netip.Addr{a.IPv4, a.IPv6})
		return nil, fmt.Errorf("ezgh-vpc-cni: wiring %s: %w", args.IfName, err)
	}
	return result(args.ContainerID, args.IfName, args.Netns, podMAC, a), nil
}

func result(containerID, ifName, netns string, podMAC net.HardwareAddr, a ipamd.AddResponse) *current.Result {
	pod := 1
	return &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: []*current.Interface{
			{Name: VethName(containerID, ifName), Mac: HostMAC(containerID, ifName).String()},
			{Name: ifName, Mac: podMAC.String(), Sandbox: netns},
		},
		// IPv4 first: kubelet's podIPs[0], so IPv4 is the pod's primary.
		IPs: []*current.IPConfig{
			{Interface: &pod, Address: net.IPNet{IP: a.IPv4.AsSlice(), Mask: net.CIDRMask(32, 32)}, Gateway: net.ParseIP(Gateway4)},
			{Interface: &pod, Address: net.IPNet{IP: a.IPv6.AsSlice(), Mask: net.CIDRMask(128, 128)}, Gateway: net.ParseIP(Gateway6)},
		},
	}
}

// prevAddrs are the addresses a previous ADD gave the pod.
func prevAddrs(c *NetConf) []netip.Addr {
	if c.PrevResult == nil {
		return nil
	}
	r, err := current.NewResultFromResult(c.PrevResult)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ip := range r.IPs {
		if a, ok := netip.AddrFromSlice(ip.Address.IP); ok {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// cmdDel takes the pod's datapath down first, then frees its addresses: ipamd never hands out
// an address still wired to a veth. Both halves are idempotent, the netns may be gone.
func cmdDel(args *skel.CmdArgs) error {
	c, err := parse(args)
	if err != nil {
		return err
	}
	if err := Unwire(args.ContainerID, args.IfName, prevAddrs(c)); err != nil {
		return fmt.Errorf("ezgh-vpc-cni: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return ipamd.Client{Socket: c.Socket}.Del(ctx, args.ContainerID, args.IfName)
}

func cmdCheck(args *skel.CmdArgs) error {
	c, err := parse(args)
	if err != nil {
		return err
	}
	addrs := prevAddrs(c)
	if len(addrs) == 0 {
		return fmt.Errorf("ezgh-vpc-cni: CHECK needs the previous result")
	}
	if err := Check(args.ContainerID, args.IfName, addrs); err != nil {
		return fmt.Errorf("ezgh-vpc-cni: %w", err)
	}
	return nil
}
