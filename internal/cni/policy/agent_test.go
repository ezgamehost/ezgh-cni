package policy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ezgamehost/ezgh-cni/internal/cni/nft"
)

func kpod(name, node, ip string, phase corev1.PodPhase, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name, Labels: labels},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: phase, PodIPs: []corev1.PodIP{{IP: ip}}}}
}

type applied struct {
	at      time.Time
	ruleset string
}

// start runs the agent on node ins-a against a fake API and returns what it applies. veths is
// what HostVeths would find (nil: web's), and opt adjusts the rest.
func start(t *testing.T, veths func() (map[netip.Addr]string, error), opt func(*Options), objs ...any) (*fake.Clientset, <-chan applied) {
	t.Helper()
	kube := fake.NewClientset()
	ctx, cancel := context.WithCancel(context.Background())
	for _, o := range objs {
		var err error
		switch o := o.(type) {
		case *corev1.Pod:
			_, err = kube.CoreV1().Pods(o.Namespace).Create(ctx, o, metav1.CreateOptions{})
		case *networkingv1.NetworkPolicy:
			_, err = kube.NetworkingV1().NetworkPolicies(o.Namespace).Create(ctx, o, metav1.CreateOptions{})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if veths == nil {
		veths = func() (map[netip.Addr]string, error) {
			return map[netip.Addr]string{netip.MustParseAddr("10.240.1.16"): vethWeb}, nil
		}
	}
	out := make(chan applied, 100)
	o := Options{Kube: kube, Node: "ins-a", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Veths: veths,
		Apply: func(_ context.Context, rs string) error { out <- applied{time.Now(), rs}; return nil }}
	if opt != nil {
		opt(&o)
	}
	done := make(chan error)
	go func() { done <- Run(ctx, o) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return kube, out
}

func next(t *testing.T, out <-chan applied) applied {
	t.Helper()
	select {
	case a := <-out:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("nothing applied")
		return applied{}
	}
}

func TestRecompileOnLabelChange(t *testing.T) {
	deny := pol("deny", sel("app", "web"), ingress, []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: sel("app", "web")}}}}, nil)
	// A finished pod's address may already belong to someone else: never a peer.
	done := kpod("old", "ins-b", "10.240.2.99", corev1.PodSucceeded, map[string]string{"app": "web"})
	kube, out := start(t, nil, nil, kpod("web", "ins-a", "10.240.1.16", corev1.PodRunning, map[string]string{"app": "web"}), done, &deny)
	first := next(t, out).ruleset
	if !strings.Contains(first, ": jump in_"+vethWeb) || strings.Contains(first, "10.240.2.99") {
		t.Fatal(first)
	}
	p, _ := kube.CoreV1().Pods("shop").Get(context.Background(), "web", metav1.GetOptions{})
	p.Labels = map[string]string{"app": "other"}
	if _, err := kube.CoreV1().Pods("shop").Update(context.Background(), p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := next(t, out).ruleset; strings.Contains(got, "jump") {
		t.Fatal(got)
	}
}

func TestDebounce100ms(t *testing.T) {
	kube, out := start(t, nil, nil, kpod("web", "ins-a", "10.240.1.16", corev1.PodRunning, map[string]string{"app": "web"}))
	next(t, out)
	began := time.Now()
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		p := pol(name, sel("app", "web"), ingress, nil, nil)
		if _, err := kube.NetworkingV1().NetworkPolicies("shop").Create(context.Background(), &p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	a := next(t, out)
	if d := a.at.Sub(began); d < 90*time.Millisecond || !strings.Contains(a.ruleset, ": jump in_"+vethWeb) {
		t.Fatalf("applied after %v:\n%s", d, a.ruleset)
	}
	select {
	case b := <-out:
		t.Fatalf("five changes, a second apply:\n%s", b.ruleset)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestAppliedInOneTransaction(t *testing.T) {
	// A stand-in nft on PATH records each invocation and what it read: one per change, holding the
	// old table's removal and the whole new table.
	dir := t.TempDir()
	script := "#!/bin/sh\nn=$(ls " + dir + " | grep -c '^call') ; echo \"$@\" > " + dir + "/call$n; cat > " + dir + "/stdin$n\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	deny := pol("deny", sel("app", "web"), ingress, nil, nil)
	ready := filepath.Join(t.TempDir(), "ready")
	start(t, nil, func(o *Options) { o.Apply, o.ReadyFile = nil, ready },
		kpod("web", "ins-a", "10.240.1.16", corev1.PodRunning, map[string]string{"app": "web"}), &deny)
	waitFile(t, ready)
	time.Sleep(300 * time.Millisecond)
	calls, _ := filepath.Glob(filepath.Join(dir, "call*"))
	if len(calls) != 1 {
		t.Fatalf("%d nft invocations", len(calls))
	}
	args, _ := os.ReadFile(calls[0])
	stdin, _ := os.ReadFile(filepath.Join(dir, "stdin0"))
	want := nft.Script(Table, Compile(State{Local: []Pod{{Namespace: "shop", Name: "web", Veth: vethWeb, Labels: map[string]string{"app": "web"}, IPs: addrs("10.240.1.16")}},
		All: []Pod{{Namespace: "shop", Name: "web", Labels: map[string]string{"app": "web"}, IPs: addrs("10.240.1.16")}}, Policies: []networkingv1.NetworkPolicy{deny}}))
	if string(args) != "-f -\n" || string(stdin) != want || !strings.Contains(want, "delete table inet "+Table+"\n") || !strings.Contains(want, "chain in_"+vethWeb) {
		t.Fatalf("nft %q read:\n%s", args, stdin)
	}
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no %s", path)
}

func TestIrrelevantUpdateNoRebuild(t *testing.T) {
	var builds atomic.Int32
	veths := func() (map[netip.Addr]string, error) {
		builds.Add(1)
		return map[netip.Addr]string{netip.MustParseAddr("10.240.1.16"): vethWeb}, nil
	}
	kube, out := start(t, veths, nil, kpod("web", "ins-a", "10.240.1.16", corev1.PodRunning, map[string]string{"app": "web"}))
	next(t, out)
	before := builds.Load()
	ctx := context.Background()
	p, _ := kube.CoreV1().Pods("shop").Get(ctx, "web", metav1.GetOptions{})
	p.Annotations = map[string]string{"x": "y"}
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if _, err := kube.CoreV1().Pods("shop").Update(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := builds.Load(); got != before {
		t.Fatalf("%d rebuilds for an annotation and a condition", got-before)
	}
	// A label is relevant.
	p, _ = kube.CoreV1().Pods("shop").Get(ctx, "web", metav1.GetOptions{})
	p.Labels = map[string]string{"app": "other"}
	if _, err := kube.CoreV1().Pods("shop").Update(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if builds.Load() == before {
		t.Fatal("no rebuild for a label change")
	}
}

func TestTransformKeepsOnlyWhatCompiles(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	p := kpod("web", "ins-a", "10.240.1.16", corev1.PodRunning, map[string]string{"app": "web"})
	p.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kubelet"}}
	p.Annotations = map[string]string{"big": strings.Repeat("x", 1000)}
	p.ResourceVersion = "7"
	p.Spec.Containers = []corev1.Container{{Name: "app", Image: "nginx", Env: []corev1.EnvVar{{Name: "A", Value: "b"}}, Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 80, Protocol: corev1.ProtocolTCP}}}}
	p.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "busybox"}, {Name: "proxy", RestartPolicy: &always, Ports: []corev1.ContainerPort{{Name: "admin", ContainerPort: 9901, Protocol: corev1.ProtocolTCP}}}}
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady}}
	got, err := transform(p)
	if err != nil {
		t.Fatal(err)
	}
	g := got.(*corev1.Pod)
	if g.ManagedFields != nil || g.Annotations != nil || g.Status.Conditions != nil || g.Spec.Containers[0].Image != "" || g.Spec.Containers[0].Env != nil ||
		len(g.Spec.InitContainers) != 1 || g.Spec.InitContainers[0].Ports[0].Name != "admin" ||
		g.Labels["app"] != "web" || g.ResourceVersion != "7" || g.Spec.NodeName != "ins-a" || g.Status.PodIPs[0].IP != "10.240.1.16" || g.Spec.Containers[0].Ports[0].Name != "http" {
		t.Fatalf("%+v", g)
	}
	np := pol("p", sel("app", "web"), ingress, nil, nil)
	np.ManagedFields, np.Annotations = []metav1.ManagedFieldsEntry{{Manager: "kubectl"}}, map[string]string{"a": "b"}
	if gp, _ := transform(&np); gp.(*networkingv1.NetworkPolicy).ManagedFields != nil || gp.(*networkingv1.NetworkPolicy).Annotations != nil ||
		gp.(*networkingv1.NetworkPolicy).Spec.PolicyTypes[0] != networkingv1.PolicyTypeIngress {
		t.Fatal(gp)
	}
}

func TestNamedPortFromRestartableInit(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	p := kpod("web", "ins-a", "10.240.1.16", corev1.PodRunning, map[string]string{"app": "web"})
	p.Spec.InitContainers = []corev1.Container{{Name: "once", Ports: []corev1.ContainerPort{{Name: "admin", ContainerPort: 1111, Protocol: corev1.ProtocolTCP}}},
		{Name: "proxy", RestartPolicy: &always, Ports: []corev1.ContainerPort{{Name: "admin", ContainerPort: 9901, Protocol: corev1.ProtocolTCP}}}}
	allow := pol("admin", sel("app", "web"), ingress, []networkingv1.NetworkPolicyIngressRule{{Ports: []networkingv1.NetworkPolicyPort{port(tcp, intstr.FromString("admin"), 0)}}}, nil)
	_, out := start(t, nil, nil, p, &allow)
	if rs := next(t, out).ruleset; !strings.Contains(rs, "tcp . 9901") || strings.Contains(rs, "1111") {
		t.Fatal(rs)
	}
}

func TestMissingVethRetried(t *testing.T) {
	// The pod's address is in the API before HostVeths sees its route: the agent says so and
	// looks again each second until its chain lands.
	var calls atomic.Int32
	veths := func() (map[netip.Addr]string, error) {
		if calls.Add(1) < 3 {
			return map[netip.Addr]string{}, nil
		}
		return map[netip.Addr]string{netip.MustParseAddr("10.240.1.16"): vethWeb}, nil
	}
	deny := pol("deny", sel("app", "web"), ingress, nil, nil)
	_, out := start(t, veths, nil, kpod("web", "ins-a", "10.240.1.16", corev1.PodRunning, map[string]string{"app": "web"}), &deny)
	if rs := next(t, out).ruleset; strings.Contains(rs, "jump") {
		t.Fatal(rs)
	}
	if rs := next(t, out).ruleset; !strings.Contains(rs, ": jump in_"+vethWeb) {
		t.Fatal(rs)
	}
	if n := calls.Load(); n < 3 {
		t.Fatalf("%d looks", n)
	}
}

func TestApplyFailureBacksOffAndReadiness(t *testing.T) {
	var mu sync.Mutex
	var at []time.Time
	fail := true
	ready := filepath.Join(t.TempDir(), "ready")
	ok := make(chan struct{}, 10)
	start(t, nil, func(o *Options) {
		o.ReadyFile, o.RetryBase = ready, 50*time.Millisecond
		o.Apply = func(context.Context, string) error {
			mu.Lock()
			defer mu.Unlock()
			at = append(at, time.Now())
			if fail {
				return errors.New("nft: boom")
			}
			ok <- struct{}{}
			return nil
		}
	}, kpod("web", "ins-a", "10.240.1.16", corev1.PodRunning, map[string]string{"app": "web"}))
	time.Sleep(800 * time.Millisecond)
	mu.Lock()
	// 0, +50, +150, +350, +750 ms: doubling, never a tight loop.
	if len(at) < 3 || len(at) > 5 {
		t.Fatalf("%d attempts", len(at))
	}
	for i := 2; i < len(at); i++ {
		if at[i].Sub(at[i-1]) < at[i-1].Sub(at[i-2])*3/2 {
			t.Fatalf("attempt %d after %v, the one before after %v", i, at[i].Sub(at[i-1]), at[i-1].Sub(at[i-2]))
		}
	}
	if _, err := os.Stat(ready); err == nil {
		t.Fatal("ready while failing")
	}
	fail = false
	mu.Unlock()
	select {
	case <-ok:
	case <-time.After(5 * time.Second):
		t.Fatal("never applied")
	}
	waitFile(t, ready)
}
