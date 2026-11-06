// Command ezgh-vpc-cni is the node's pod networking: the CNI
// plugin when containerd runs it (CNI_COMMAND set, no arguments), else a subcommand of the vpc-cni
// add-on's DaemonSet: install (the init container), ipamd, policy.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ezgamehost/ezgh-cni/internal/cni/ipamd"
	"github.com/ezgamehost/ezgh-cni/internal/cni/plugin"
	"github.com/ezgamehost/ezgh-cni/internal/cni/policy"
	"github.com/ezgamehost/ezgh-cni/internal/kit/logging"
	"github.com/ezgamehost/ezgh-cni/internal/nodeauth/imds"
)

const (
	binPath = "/opt/cni/bin/ezgh-vpc-cni"
	// portmapPath is upstream's portmap in the vpc-cni image (Dockerfile).
	portmapPath = "/portmap"
	kubeconfig  = "/etc/kubernetes/ezgh/cluster.kubeconfig"
)

func main() {
	if os.Getenv("CNI_COMMAND") != "" {
		plugin.Main()
		return
	}
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "plugin":
		plugin.Main()
	case "install":
		err = install()
	case "ipamd":
		err = runIpamd()
	case "policy":
		err = runPolicy()
	default:
		err = fmt.Errorf("usage: ezgh-vpc-cni plugin|install|ipamd|policy")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ezgh-vpc-cni:", err)
		os.Exit(1)
	}
}

// install copies this binary and the image's upstream portmap (hostPort, chained after
// ezgh-vpc-cni in the conflist) to the node's CNI directory.
func install() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	return installInto(filepath.Dir(binPath), self, portmapPath)
}

func installInto(dir, self, portmap string) error {
	for name, src := range map[string]string{"ezgh-vpc-cni": self, "portmap": portmap} {
		if err := copyFile(src, filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("install %s: %w", name, err)
		}
	}
	return nil
}

// copyFile writes then renames, so containerd never runs half a file.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	_, err = io.Copy(out, in)
	for _, step := range []func() error{func() error { return err }, func() error { return out.Chmod(0o755) }, out.Sync} {
		if err := step(); err != nil {
			out.Close()
			return err
		}
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(out.Name(), dst)
}

func runIpamd() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	kube, err := client()
	if err != nil {
		return err
	}
	return ipamd.Run(ctx, ipamd.Options{IMDS: &imds.Client{}, Kube: kube, Log: logging.New(os.Stderr, "ezgh-vpc-cni", false)})
}

// runPolicy is the NetworkPolicy agent; the DaemonSet gives it the node's name.
func runPolicy() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	node := os.Getenv("NODE_NAME")
	if node == "" {
		return fmt.Errorf("policy: NODE_NAME isn't set")
	}
	kube, err := client()
	if err != nil {
		return err
	}
	return policy.Run(ctx, policy.Options{Kube: kube, Node: node, ReadyFile: "/tmp/ezgh-policy-ready", Log: logging.New(os.Stderr, "ezgh-vpc-cni", false)})
}

func client() (kubernetes.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}
