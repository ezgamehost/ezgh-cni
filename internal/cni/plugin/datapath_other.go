//go:build !linux

package plugin

import (
	"errors"
	"net"
	"net/netip"

	"github.com/ezgamehost/ezgh-cni/internal/cni/ipamd"
)

var errLinux = errors.New("the CNI plugin runs on Linux only")

func Wire(string, string, string, ipamd.AddResponse) (net.HardwareAddr, error) { return nil, errLinux }
func Unwire(string, string, []netip.Addr) error                                { return errLinux }
func Check(string, string, []netip.Addr) error                                 { return errLinux }
