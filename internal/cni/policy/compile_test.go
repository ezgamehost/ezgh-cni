package policy

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const vethWeb, vethDB = "ezp0123456789ab", "ezpcdef01234567"

func addrs(s ...string) []netip.Addr {
	var a []netip.Addr
	for _, x := range s {
		a = append(a, netip.MustParseAddr(x))
	}
	return a
}

var (
	web  = Pod{Namespace: "shop", Name: "web", Veth: vethWeb, Labels: map[string]string{"app": "web"}, IPs: addrs("10.240.1.16", "fdcc:1:2:1:c4a4::16"), Ports: []NamedPort{{"http", "TCP", 8080}, {"dns", "UDP", 5353}}}
	db   = Pod{Namespace: "shop", Name: "db", Veth: vethDB, Labels: map[string]string{"app": "db"}, IPs: addrs("10.240.1.17", "fdcc:1:2:1:c4a4::17"), Ports: []NamedPort{{"http", "TCP", 5432}}}
	api  = Pod{Namespace: "shop", Name: "api", Labels: map[string]string{"app": "api"}, IPs: addrs("10.240.2.20"), Ports: []NamedPort{{"http", "TCP", 9000}}}
	prom = Pod{Namespace: "ops", Name: "prom", Labels: map[string]string{"app": "prom"}, IPs: addrs("10.240.2.21", "fdcc:1:2:2::21")}
	host = Pod{Namespace: "shop", Name: "agent", Labels: map[string]string{"app": "web"}, IPs: addrs("10.240.1.5"), HostNetwork: true, Ports: []NamedPort{{"http", "TCP", 80}}}
	none = Pod{Namespace: "shop", Name: "pending", Veth: "ezp999999999999", Labels: map[string]string{"app": "web"}}
)

func state(pols ...networkingv1.NetworkPolicy) State {
	return State{
		Local: []Pod{web, db, host, none},
		All:   []Pod{web, db, api, prom, host, none},
		Namespaces: map[string]map[string]string{
			"shop": {"kubernetes.io/metadata.name": "shop", "team": "shop"},
			"ops":  {"kubernetes.io/metadata.name": "ops", "team": "ops"},
		},
		Policies: pols,
	}
}

func sel(kv ...string) *metav1.LabelSelector {
	m := map[string]string{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return &metav1.LabelSelector{MatchLabels: m}
}

func pol(name string, target *metav1.LabelSelector, types []networkingv1.PolicyType, in []networkingv1.NetworkPolicyIngressRule, out []networkingv1.NetworkPolicyEgressRule) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
		Spec: networkingv1.NetworkPolicySpec{PodSelector: *target, PolicyTypes: types, Ingress: in, Egress: out}}
}

var (
	ingress = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	egress  = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
	tcp     = corev1.ProtocolTCP
	udp     = corev1.ProtocolUDP
	sctp    = corev1.ProtocolSCTP
)

func port(proto corev1.Protocol, p intstr.IntOrString, end int32) networkingv1.NetworkPolicyPort {
	pp := networkingv1.NetworkPolicyPort{Protocol: &proto, Port: &p}
	if end != 0 {
		pp.EndPort = &end
	}
	return pp
}

// golden compares Compile(s) with testdata/<name>.nft; UPDATE_GOLDEN=1 rewrites it.
func golden(t *testing.T, s State) string {
	t.Helper()
	file := "testdata/" + strings.TrimPrefix(t.Name(), "Test") + ".nft"
	got := Compile(s)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s differs:\n%s", file, got)
	}
	return got
}

func TestNoPolicyAllowsAll(t *testing.T) {
	if out := golden(t, state()); strings.Contains(out, "jump") {
		t.Fatal(out)
	}
}

func TestIngressDefaultDeny(t *testing.T) {
	out := golden(t, state(pol("deny", &metav1.LabelSelector{}, ingress, nil, nil)))
	// Both local pods, nothing for hostNetwork or the pod without an address; no egress chains.
	if strings.Count(out, ": jump in_") != 2 || strings.Contains(out, "jump out_") || strings.Contains(out, "return") {
		t.Fatal(out)
	}
}

func TestEgressDefaultDeny(t *testing.T) {
	out := golden(t, state(pol("deny", sel("app", "web"), egress, nil, nil)))
	if !strings.Contains(out, `iifname vmap { "`+vethWeb+`" : jump out_`+vethWeb+` }`) || strings.Contains(out, "jump in_") || strings.Contains(out, vethDB) {
		t.Fatal(out)
	}
}

func TestPolicyTypesDefaulting(t *testing.T) {
	golden(t, state(
		pol("in-only", sel("app", "web"), nil, []networkingv1.NetworkPolicyIngressRule{{}}, nil),
		pol("both", sel("app", "db"), nil, nil, []networkingv1.NetworkPolicyEgressRule{{}}),
	))
}

func TestPodSelectorSameNamespace(t *testing.T) {
	// app=prom lives in ops: a bare podSelector never reaches across namespaces.
	golden(t, state(pol("p", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{
		From: []networkingv1.NetworkPolicyPeer{{PodSelector: sel("app", "web")}, {PodSelector: sel("app", "prom")}},
	}}, nil)))
}

func TestNamespaceSelector(t *testing.T) {
	golden(t, state(pol("p", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{
		From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: sel("team", "ops")}},
	}}, nil)))
}

func TestBothSelectorsAnd(t *testing.T) {
	// team=shop has web, db and api; only api matches both.
	golden(t, state(pol("p", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{
		From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: sel("team", "shop"), PodSelector: sel("app", "api")}},
	}}, nil)))
}

func TestIPBlockExcept(t *testing.T) {
	golden(t, state(pol("p", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{
		From: []networkingv1.NetworkPolicyPeer{
			{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.240.2.0/24", "10.9.0.0/16"}}},
			{IPBlock: &networkingv1.IPBlock{CIDR: "2001:db8::/32"}},
		},
	}}, nil)))
}

func TestPortRangeEndPort(t *testing.T) {
	golden(t, state(pol("p", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{
		// 8080 overlaps the range: nft must still load it (TestGoldensLoad).
		Ports: []networkingv1.NetworkPolicyPort{port(tcp, intstr.FromInt32(8000), 8100), port(tcp, intstr.FromInt32(8080), 0), port(udp, intstr.FromInt32(53), 0), {Protocol: &udp}},
	}}, nil)))
}

func TestNamedPortIngress(t *testing.T) {
	// "http" is 8080 on web and 5432 on db; "dns" only on web, and only as UDP.
	out := golden(t, state(pol("p", &metav1.LabelSelector{}, ingress, []networkingv1.NetworkPolicyIngressRule{{
		Ports: []networkingv1.NetworkPolicyPort{port(tcp, intstr.FromString("http"), 0), port(tcp, intstr.FromString("dns"), 0)},
	}}, nil)))
	if !strings.Contains(out, "meta l4proto . th dport { tcp . 8080 } return") || !strings.Contains(out, "meta l4proto . th dport { tcp . 5432 } return") || strings.Contains(out, "5353") {
		t.Fatal(out)
	}
}

func TestNamedPortEgress(t *testing.T) {
	// Destinations in shop with a TCP "http": web, db, api; the hostNetwork agent never.
	out := golden(t, state(pol("p", sel("app", "web"), egress, nil, []networkingv1.NetworkPolicyEgressRule{{
		To:    []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}},
		Ports: []networkingv1.NetworkPolicyPort{port(tcp, intstr.FromString("http"), 0)},
	}})))
	if !strings.Contains(out, "10.240.2.20 . tcp . 9000") || strings.Contains(out, "10.240.1.5 ") {
		t.Fatal(out)
	}
}

func TestSCTP(t *testing.T) {
	golden(t, state(pol("p", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{
		Ports: []networkingv1.NetworkPolicyPort{port(sctp, intstr.FromInt32(3868), 0)},
	}}, nil)))
}

func TestDualStack(t *testing.T) {
	out := golden(t, state(pol("p", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{
		From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}, PodSelector: sel("app", "prom")}},
	}}, nil)))
	if !strings.Contains(out, "elements = { 10.240.2.21 }") || !strings.Contains(out, "elements = { fdcc:1:2:2::21 }") ||
		!strings.Contains(out, "ip saddr @") || !strings.Contains(out, "ip6 saddr @") {
		t.Fatal(out)
	}
}

func TestUnionOfPolicies(t *testing.T) {
	golden(t, state(
		pol("a", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: sel("app", "web")}}}}, nil),
		pol("b", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{Ports: []networkingv1.NetworkPolicyPort{port(tcp, intstr.FromInt32(5432), 0)}}}, nil),
	))
}

func TestHostNetworkNotATarget(t *testing.T) {
	// The agent shares app=web; it gets no chain, and isn't a peer either.
	out := golden(t, state(pol("p", sel("app", "web"), ingress, []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: sel("app", "web")}}}}, nil)))
	if strings.Contains(out, "10.240.1.5") || strings.Count(out, ": jump") != 1 {
		t.Fatal(out)
	}
}

func TestPodWithoutIPSkipped(t *testing.T) {
	out := Compile(state(pol("deny", sel("app", "web"), ingress, nil, nil)))
	if strings.Contains(out, none.Veth) {
		t.Fatal(out)
	}
}

func TestDeterministic(t *testing.T) {
	a := state(pol("a", sel("app", "db"), ingress, nil, nil), pol("b", sel("app", "web"), egress, nil, nil))
	b := state(pol("b", sel("app", "web"), egress, nil, nil), pol("a", sel("app", "db"), ingress, nil, nil))
	b.Local = []Pod{none, host, db, web}
	if Compile(a) != Compile(b) {
		t.Fatal("order changed the table")
	}
}

func TestPortsFoldedIntoOneSet(t *testing.T) {
	// One rule's ports are one match, a protocol without a port its whole range.
	out := Compile(state(pol("p", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{
		From:  []networkingv1.NetworkPolicyPeer{{PodSelector: sel("app", "web")}},
		Ports: []networkingv1.NetworkPolicyPort{port(tcp, intstr.FromInt32(8000), 8100), port(udp, intstr.FromInt32(53), 0), {Protocol: &sctp}},
	}}, nil)))
	want := "meta l4proto . th dport { sctp . 0-65535, tcp . 8000-8100, udp . 53 } return"
	if strings.Count(out, want) != 2 || strings.Count(out, "return") != 2 {
		t.Fatal(out)
	}
}

func TestPeerSetWrittenOnce(t *testing.T) {
	// Both local pods are targets of one rule: its peers are one named set, written once.
	out := Compile(state(pol("p", &metav1.LabelSelector{}, ingress, []networkingv1.NetworkPolicyIngressRule{{
		From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}}},
	}}, nil)))
	if strings.Count(out, "10.240.2.21") != 1 || strings.Count(out, "ip saddr @") != 2 {
		t.Fatal(out)
	}
}

func TestTargeted(t *testing.T) {
	pols := []networkingv1.NetworkPolicy{pol("p", sel("app", "web"), egress, nil, nil)}
	if !Targeted(pols, web) || Targeted(pols, db) || Targeted(pols, host) {
		t.Fatal("targets")
	}
}
