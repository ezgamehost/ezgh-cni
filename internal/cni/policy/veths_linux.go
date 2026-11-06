package policy

import (
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// HostVeths maps each pod address to its host veth, read from the /32 and /128 routes the plugin
// keeps in main (`<addr> dev ezp…`). The API never carries the sandbox ID the veth is named from.
func HostVeths() (map[netip.Addr]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	for _, l := range links {
		if strings.HasPrefix(l.Attrs().Name, "ezp") {
			names[l.Attrs().Index] = l.Attrs().Name
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	m := map[netip.Addr]string{}
	for _, r := range routes {
		name, ok := names[r.LinkIndex]
		if !ok || r.Dst == nil {
			continue
		}
		if ones, bits := r.Dst.Mask.Size(); ones != bits {
			continue
		}
		if a, ok := netip.AddrFromSlice(r.Dst.IP); ok {
			m[a.Unmap()] = name
		}
	}
	return m, nil
}
