package plugin

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/ezgamehost/ezgh-cni/internal/cni/ipamd"
)

func hostNet(a netip.Addr) *net.IPNet {
	return &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(a.BitLen(), a.BitLen())}
}

func family(a netip.Addr) int {
	if a.Is4() {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

func podRule(a netip.Addr) *netlink.Rule {
	r := netlink.NewRule()
	r.Family, r.Dst, r.Table, r.Priority = family(a), hostNet(a), unix.RT_TABLE_MAIN, PodRulePref
	return r
}

// Wire makes the pod's veth and routes; it answers the pod side's MAC.
func Wire(netnsPath, containerID, ifName string, a ipamd.AddResponse) (net.HardwareAddr, error) {
	netns, err := ns.GetNS(netnsPath)
	if err != nil {
		return nil, err
	}
	defer netns.Close()
	host, mac := VethName(containerID, ifName), HostMAC(containerID, ifName)
	// What a failed ADD left behind goes first.
	if l, err := netlink.LinkByName(host); err == nil {
		if err := netlink.LinkDel(l); err != nil {
			return nil, err
		}
	}
	if err := netns.Do(func(ns.NetNS) error {
		if l, err := netlink.LinkByName(ifName); err == nil {
			return netlink.LinkDel(l)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: host, HardwareAddr: mac, MTU: a.MTU},
		PeerName: ifName, PeerMTU: uint32(a.MTU), PeerNamespace: netlink.NsFd(int(netns.Fd()))}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("veth %s: %w", host, err)
	}
	l, err := netlink.LinkByName(host)
	if err != nil {
		return nil, err
	}
	gw6, _ := netlink.ParseAddr(Gateway6 + "/64")
	gw6.Flags = unix.IFA_F_NODAD
	if err := netlink.AddrAdd(l, gw6); err != nil {
		return nil, fmt.Errorf("%s on %s: %w", Gateway6, host, err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return nil, err
	}
	var podMAC net.HardwareAddr
	if err := netns.Do(func(ns.NetNS) error {
		p, err := netlink.LinkByName(ifName)
		if err != nil {
			return err
		}
		podMAC = p.Attrs().HardwareAddr
		lo, err := netlink.LinkByName("lo")
		if err == nil {
			err = netlink.LinkSetUp(lo)
		}
		v6 := &netlink.Addr{IPNet: hostNet(a.IPv6), Flags: unix.IFA_F_NODAD}
		gw4 := net.ParseIP(Gateway4)
		for _, step := range []func() error{
			func() error { return err },
			func() error { return netlink.AddrAdd(p, &netlink.Addr{IPNet: hostNet(a.IPv4)}) },
			func() error { return netlink.AddrAdd(p, v6) },
			func() error { return netlink.LinkSetUp(p) },
			func() error {
				return netlink.RouteAdd(&netlink.Route{LinkIndex: p.Attrs().Index, Dst: &net.IPNet{IP: gw4, Mask: net.CIDRMask(32, 32)}, Scope: netlink.SCOPE_LINK})
			},
			func() error { return netlink.RouteAdd(&netlink.Route{LinkIndex: p.Attrs().Index, Gw: gw4}) },
			func() error {
				return netlink.NeighAdd(&netlink.Neigh{LinkIndex: p.Attrs().Index, Family: netlink.FAMILY_V4, IP: gw4, HardwareAddr: mac, State: netlink.NUD_PERMANENT})
			},
			func() error {
				return netlink.RouteAdd(&netlink.Route{LinkIndex: p.Attrs().Index, Gw: net.ParseIP(Gateway6), Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}})
			},
		} {
			if err := step(); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("pod side: %w", err)
	}
	for _, addr := range []netip.Addr{a.IPv4, a.IPv6} {
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: l.Attrs().Index, Dst: hostNet(addr), Scope: netlink.SCOPE_LINK}); err != nil {
			return nil, fmt.Errorf("route to %s: %w", addr, err)
		}
		_ = netlink.RuleDel(podRule(addr))
		if err := netlink.RuleAdd(podRule(addr)); err != nil {
			return nil, fmt.Errorf("rule to %s: %w", addr, err)
		}
	}
	return podMAC, nil
}

// Unwire removes the pod's rules and its host veth (the peer and routes go with it). addrs adds
// to the addresses routed to the veth, for a veth already gone.
func Unwire(containerID, ifName string, addrs []netip.Addr) error {
	host := VethName(containerID, ifName)
	l, err := netlink.LinkByName(host)
	if err == nil {
		routes, err := netlink.RouteList(l, netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		for _, r := range routes {
			if r.Dst == nil || !isHost(r.Dst) {
				continue
			}
			if a, ok := netip.AddrFromSlice(r.Dst.IP); ok {
				addrs = append(addrs, a.Unmap())
			}
		}
	} else if !errors.As(err, &netlink.LinkNotFoundError{}) {
		return err
	}
	for _, a := range addrs {
		if a.IsValid() {
			_ = netlink.RuleDel(podRule(a)) // absent is fine
		}
	}
	if l != nil {
		if err := netlink.LinkDel(l); err != nil && !errors.As(err, &netlink.LinkNotFoundError{}) {
			return err
		}
	}
	return nil
}

func isHost(n *net.IPNet) bool { ones, bits := n.Mask.Size(); return ones == bits }

// Check finds what of the host side is missing: the veth with its MAC, each address's route and
// pref 512 rule.
func Check(containerID, ifName string, addrs []netip.Addr) error {
	host := VethName(containerID, ifName)
	l, err := netlink.LinkByName(host)
	if err != nil {
		return fmt.Errorf("host veth %s: %w", host, err)
	}
	if l.Attrs().HardwareAddr.String() != HostMAC(containerID, ifName).String() {
		return fmt.Errorf("host veth %s has MAC %s, the pod's neighbour is %s", host, l.Attrs().HardwareAddr, HostMAC(containerID, ifName))
	}
	for _, a := range addrs {
		routes, err := netlink.RouteListFiltered(family(a), &netlink.Route{Dst: hostNet(a), LinkIndex: l.Attrs().Index}, netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
		if err != nil || len(routes) == 0 {
			return fmt.Errorf("route %s dev %s missing", a, host)
		}
		rules, err := netlink.RuleListFiltered(family(a), &netlink.Rule{Priority: PodRulePref}, netlink.RT_FILTER_PRIORITY)
		if err != nil {
			return err
		}
		found := false
		for _, r := range rules {
			found = found || r.Dst != nil && r.Dst.String() == hostNet(a).String() && r.Table == unix.RT_TABLE_MAIN
		}
		if !found {
			return fmt.Errorf("rule to %s lookup main pref %d missing", a, PodRulePref)
		}
	}
	return nil
}
