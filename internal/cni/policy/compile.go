// Package policy is the node's NetworkPolicy agent: it
// watches Pods, Namespaces and NetworkPolicies and keeps table inet ezgh_policy, which isolates
// the node's own pods. The table sits in forward after ezgh_cni (priority 0), so it sees Service
// traffic after kube-proxy's DNAT; the node's own traffic to its pods never crosses forward and
// stays allowed, as upstream requires. hostNetwork pods are never targets or peers.
package policy

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const Table = "ezgh_policy"

type Pod struct {
	Namespace, Name, Veth string
	Labels                map[string]string
	IPs                   []netip.Addr
	HostNetwork           bool
	Ports                 []NamedPort
}

type NamedPort struct {
	Name, Protocol string
	Port           int32
}

// State is what the table is compiled from: Local are this node's pods (with their host veths), All
// every pod in the cluster, Namespaces each namespace's labels.
type State struct {
	Local, All []Pod
	Namespaces map[string]map[string]string
	Policies   []networkingv1.NetworkPolicy
}

// Compile is the whole table. A pod's chain returns when a rule allows the packet and rejects it
// otherwise, so a packet between two isolated pods on this node passes the receiver's ingress
// chain and then the sender's egress chain; replies are conntrack's. Refusals answer at once so
// nothing waits on a timeout: TCP with a reset (IPv6 TCP sits out a SYN retransmit on an ICMPv6
// refusal), the rest with ICMP.
//
// Each rule is resolved once, however many local pods it targets: its pod peers are one named set
// per family, its ports one `meta l4proto . th dport` set, and egress named ports one
// `addr . proto . port` set per family. Only ingress named ports depend on the target pod.
func Compile(s State) string {
	pols := slices.Clone(s.Policies)
	slices.SortFunc(pols, func(a, b networkingv1.NetworkPolicy) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	local := slices.Clone(s.Local)
	slices.SortFunc(local, func(a, b Pod) int { return cmp.Compare(a.Veth, b.Veth) })

	c := &compiler{s: s, done: map[string]*rule{}}
	var inMap, outMap []string
	var chains strings.Builder
	for _, p := range local {
		if p.HostNetwork || p.Veth == "" || len(p.IPs) == 0 {
			continue
		}
		var in, out []string
		isoIn, isoOut := false, false
		for i, pol := range pols {
			doIn, doOut := isolates(&pol, p)
			if doIn {
				isoIn = true
				for j, r := range pol.Spec.Ingress {
					in = append(in, c.rule(fmt.Sprintf("p%d_in%d", i, j), pol.Namespace, r.From, r.Ports, "saddr").lines(&p)...)
				}
			}
			if doOut {
				isoOut = true
				for j, r := range pol.Spec.Egress {
					out = append(out, c.rule(fmt.Sprintf("p%d_out%d", i, j), pol.Namespace, r.To, r.Ports, "daddr").lines(nil)...)
				}
			}
		}
		for _, ch := range []struct {
			iso    bool
			prefix string
			vmap   *[]string
			rules  []string
		}{{isoIn, "in_", &inMap, in}, {isoOut, "out_", &outMap, out}} {
			if !ch.iso {
				continue
			}
			*ch.vmap = append(*ch.vmap, fmt.Sprintf("%q : jump %s%s", p.Veth, ch.prefix, p.Veth))
			fmt.Fprintf(&chains, "\tchain %s%s {\n", ch.prefix, p.Veth)
			for _, r := range ch.rules {
				fmt.Fprintf(&chains, "\t\t%s\n", r)
			}
			chains.WriteString("\t\tmeta l4proto tcp reject with tcp reset\n\t\treject with icmpx type admin-prohibited\n\t}\n")
		}
	}
	var fwd strings.Builder
	for _, m := range []struct {
		match string
		el    []string
	}{{"oifname", inMap}, {"iifname", outMap}} {
		if len(m.el) > 0 {
			fmt.Fprintf(&fwd, "\t\t%s vmap { %s }\n", m.match, strings.Join(m.el, ", "))
		}
	}
	return "table inet " + Table + " {\n" +
		c.sets.String() +
		"\tchain forward {\n" +
		"\t\ttype filter hook forward priority 0; policy accept;\n" +
		"\t\tct state established,related accept\n" +
		"\t\tct state invalid drop\n" +
		fwd.String() +
		"\t}\n" +
		chains.String() +
		"}\n"
}

// Targeted reports whether any policy isolates p, ingress or egress.
func Targeted(pols []networkingv1.NetworkPolicy, p Pod) bool {
	if p.HostNetwork {
		return false
	}
	for i := range pols {
		if in, out := isolates(&pols[i], p); in || out {
			return true
		}
	}
	return false
}

// isolates says which of p's directions pol isolates. policyTypes defaults as the API does:
// Ingress always, Egress when there are egress rules.
func isolates(pol *networkingv1.NetworkPolicy, p Pod) (in, out bool) {
	if pol.Namespace != p.Namespace || !matches(selector(&pol.Spec.PodSelector), p.Labels) {
		return false, false
	}
	if len(pol.Spec.PolicyTypes) == 0 {
		return true, len(pol.Spec.Egress) > 0
	}
	return slices.Contains(pol.Spec.PolicyTypes, networkingv1.PolicyTypeIngress), slices.Contains(pol.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
}

// selector is nil (matching nothing) when sel doesn't parse.
func selector(sel *metav1.LabelSelector) labels.Selector {
	s, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return nil
	}
	return s
}

func matches(s labels.Selector, l map[string]string) bool {
	return s != nil && s.Matches(labels.Set(l))
}

type compiler struct {
	s    State
	sets strings.Builder
	done map[string]*rule
}

// rule is one policy rule, resolved.
type rule struct {
	peers  []string    // peer matches, "" for any
	any    bool        // no ports listed
	ports  []portRange // numeric ports
	named  []networkingv1.NetworkPolicyPort
	egress []string // egress named ports: whole lines
}

type block struct {
	cidr   netip.Prefix
	except []netip.Prefix
}

func (c *compiler) rule(name, namespace string, list []networkingv1.NetworkPolicyPeer, ports []networkingv1.NetworkPolicyPort, dir string) *rule {
	if r, ok := c.done[name]; ok {
		return r
	}
	r := &rule{any: len(ports) == 0}
	c.done[name] = r

	// Peers: pod addresses (in one named set per family) and IP blocks.
	anyPeer := len(list) == 0
	var pods []netip.Addr
	var blocks []block
	for _, peer := range list {
		if b := peer.IPBlock; b != nil {
			cidr, err := netip.ParsePrefix(b.CIDR)
			if err != nil {
				continue
			}
			bl := block{cidr: cidr.Masked()}
			for _, e := range b.Except {
				if ep, err := netip.ParsePrefix(e); err == nil {
					bl.except = append(bl.except, ep.Masked())
				}
			}
			blocks = append(blocks, bl)
			continue
		}
		var nsSel, podSel labels.Selector
		if peer.NamespaceSelector != nil {
			nsSel = selector(peer.NamespaceSelector)
		}
		if peer.PodSelector != nil {
			podSel = selector(peer.PodSelector)
		}
		for _, p := range c.s.All {
			if p.HostNetwork {
				continue
			}
			nsOK := p.Namespace == namespace
			if peer.NamespaceSelector != nil {
				nsOK = matches(nsSel, c.s.Namespaces[p.Namespace])
			}
			if nsOK && (peer.PodSelector == nil || matches(podSel, p.Labels)) {
				pods = append(pods, p.IPs...)
			}
		}
	}
	slices.SortFunc(pods, netip.Addr.Compare)
	pods = slices.Compact(pods)
	has := func(a netip.Addr) bool {
		if anyPeer || slices.Contains(pods, a) {
			return true
		}
		for _, b := range blocks {
			if b.cidr.Contains(a) && !slices.ContainsFunc(b.except, func(e netip.Prefix) bool { return e.Contains(a) }) {
				return true
			}
		}
		return false
	}
	if anyPeer {
		r.peers = []string{""}
	}
	// A rule whose ports are all named egress ports matches through its named sets only.
	usesPeers := len(ports) == 0 || slices.ContainsFunc(ports, func(pp networkingv1.NetworkPolicyPort) bool {
		return pp.Port == nil || pp.Port.Type == intstr.Int || dir == "saddr"
	})
	for _, fam := range []string{"ip", "ip6"} {
		if !usesPeers {
			break
		}
		var el []string
		for _, a := range pods {
			if family(a) == fam {
				el = append(el, a.String())
			}
		}
		if len(el) > 0 {
			set := name + "_" + fam
			c.set(set, map[string]string{"ip": "ipv4_addr", "ip6": "ipv6_addr"}[fam], el)
			r.peers = append(r.peers, fmt.Sprintf("%s %s @%s", fam, dir, set))
		}
	}
	for _, b := range blocks {
		fam := family(b.cidr.Addr())
		e := fmt.Sprintf("%s %s %s", fam, dir, b.cidr)
		var ex []string
		for _, x := range b.except {
			if family(x.Addr()) == fam {
				ex = append(ex, x.String())
			}
		}
		if len(ex) > 0 {
			e += fmt.Sprintf(" %s %s != { %s }", fam, dir, strings.Join(ex, ", "))
		}
		r.peers = append(r.peers, e)
	}

	// Ports.
	var egressNamed []networkingv1.NetworkPolicyPort
	for _, pp := range ports {
		pr := proto(pp.Protocol)
		switch {
		case pp.Port == nil:
			r.ports = append(r.ports, portRange{pr, 0, 65535})
		case pp.Port.Type == intstr.Int && pp.EndPort != nil:
			r.ports = append(r.ports, portRange{pr, pp.Port.IntVal, *pp.EndPort})
		case pp.Port.Type == intstr.Int:
			r.ports = append(r.ports, portRange{pr, pp.Port.IntVal, pp.Port.IntVal})
		case dir == "saddr":
			r.named = append(r.named, pp)
		default:
			egressNamed = append(egressNamed, pp)
		}
	}
	if len(egressNamed) > 0 {
		el := map[string][]string{}
		for _, p := range c.s.All {
			if p.HostNetwork {
				continue
			}
			for _, pp := range egressNamed {
				for _, port := range namedPort(p, pp) {
					for _, a := range p.IPs {
						if has(a) {
							el[family(a)] = append(el[family(a)], fmt.Sprintf("%s . %s . %d", a, port.proto, port.lo))
						}
					}
				}
			}
		}
		for _, fam := range []string{"ip", "ip6"} {
			if e := el[fam]; len(e) > 0 {
				set := name + "_named_" + fam
				c.set(set, map[string]string{"ip": "ipv4_addr", "ip6": "ipv6_addr"}[fam]+" . inet_proto . inet_service", e)
				r.egress = append(r.egress, fmt.Sprintf("%s daddr . meta l4proto . th dport @%s return", fam, set))
			}
		}
	}
	return r
}

// lines are the rule's nft lines in target's chain (target set for ingress, whose named ports it
// resolves).
func (r *rule) lines(target *Pod) []string {
	out := slices.Clone(r.egress)
	portMatch := ""
	if !r.any {
		el := slices.Clone(r.ports)
		if target != nil {
			for _, pp := range r.named {
				el = append(el, namedPort(*target, pp)...)
			}
		}
		if len(el) == 0 {
			return out
		}
		portMatch = "meta l4proto . th dport { " + strings.Join(merge(el), ", ") + " }"
	}
	for _, pe := range r.peers {
		out = append(out, strings.Join(slices.DeleteFunc([]string{pe, portMatch, "return"}, func(x string) bool { return x == "" }), " "))
	}
	return out
}

type portRange struct {
	proto  string
	lo, hi int32
}

// merge renders ranges as set elements, overlapping and adjacent ones joined: an interval set
// refuses overlaps.
func merge(rs []portRange) []string {
	rs = slices.Clone(rs)
	slices.SortFunc(rs, func(a, b portRange) int { return cmp.Or(cmp.Compare(a.proto, b.proto), cmp.Compare(a.lo, b.lo)) })
	var m []portRange
	for _, r := range rs {
		if n := len(m); n > 0 && m[n-1].proto == r.proto && r.lo <= m[n-1].hi+1 {
			m[n-1].hi = max(m[n-1].hi, r.hi)
			continue
		}
		m = append(m, r)
	}
	out := make([]string, len(m))
	for i, r := range m {
		out[i] = fmt.Sprintf("%s . %d", r.proto, r.lo)
		if r.hi != r.lo {
			out[i] += fmt.Sprintf("-%d", r.hi)
		}
	}
	return out
}

// namedPort is pp's named port on p.
func namedPort(p Pod, pp networkingv1.NetworkPolicyPort) []portRange {
	pr := proto(pp.Protocol)
	var out []portRange
	for _, np := range p.Ports {
		if np.Name == pp.Port.StrVal && strings.EqualFold(cmp.Or(np.Protocol, "TCP"), pr) {
			out = append(out, portRange{pr, np.Port, np.Port})
		}
	}
	return out
}

func (c *compiler) set(name, typ string, el []string) {
	slices.Sort(el)
	fmt.Fprintf(&c.sets, "\tset %s {\n\t\ttype %s\n\t\telements = { %s }\n\t}\n", name, typ, strings.Join(slices.Compact(el), ", "))
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "ip"
	}
	return "ip6"
}

func proto(p *corev1.Protocol) string {
	if p == nil || *p == "" {
		return "tcp"
	}
	return strings.ToLower(string(*p))
}
