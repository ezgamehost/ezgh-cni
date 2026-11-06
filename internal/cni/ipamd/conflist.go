package ipamd

// conflist is containerd's network config, written once the pod network is up and never removed
// (containerd reports NotReady without one). Upstream portmap (nftables) follows ezgh-vpc-cni for
// hostPort, reading the pod's addresses from its result.
const conflist = `{"cniVersion":"1.0.0","name":"ezgh-vpc-cni","plugins":[{"type":"ezgh-vpc-cni","socket":"/run/ezgh-vpc-cni/ipamd.sock"},{"type":"portmap","backend":"nftables","capabilities":{"portMappings":true}}]}
`

// PIA is the pod identity agent's address: local on the node, so pod
// traffic to it is input, never forwarded. IPv4 only.
const (
	PIALink    = "ezgh-pia"
	PIAAddress = "169.254.170.23"
	// PrefixRulePref is each delegated prefix's `from <prefix> lookup <table> suppress_prefixlength 0`.
	PrefixRulePref = 1536
)

// Kernel is Netlink on the node (Linux).
type Kernel struct{}
