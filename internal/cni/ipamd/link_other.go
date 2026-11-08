//go:build !linux

package ipamd

import (
	"errors"
	"net/netip"
)

var errLinux = errors.New("ipamd runs on Linux only")

func (Kernel) LinkByMAC(string) (string, error)          { return "", errLinux }
func (Kernel) EnsurePIA() error                          { return errLinux }
func (Kernel) SetPrefixRules([]netip.Prefix, int) error  { return errLinux }
func (Kernel) HostVeths() (map[netip.Addr]string, error) { return nil, errLinux }
