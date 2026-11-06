//go:build !linux

package policy

import (
	"errors"
	"net/netip"
)

func HostVeths() (map[netip.Addr]string, error) { return nil, errors.New("policy: Linux only") }
