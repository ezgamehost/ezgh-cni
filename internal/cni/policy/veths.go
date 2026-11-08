package policy

import (
	"net/netip"

	"github.com/ezgamehost/ezgh-cni/internal/cni/ipamd"
)

// HostVeths maps each pod address to its host veth, read from the /32 and /128 routes the plugin
// keeps in main (`<addr> dev ezp…`). The API never carries the sandbox ID the veth is named from.
func HostVeths() (map[netip.Addr]string, error) { return ipamd.Kernel{}.HostVeths() }
