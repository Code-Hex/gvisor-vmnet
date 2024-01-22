package vmnet

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func netaddrIPFromNetstackIP(s tcpip.Address) netip.Addr {
	switch len(s.AsSlice()) {
	case 4:
		return netip.AddrFrom4(s.As4())
	case 16:
		return netip.AddrFrom16(s.As16()).Unmap()
	}
	return netip.Addr{}
}

func ipPortOfNetstackAddr(a tcpip.Address, port uint16) (ipp netip.AddrPort, ok bool) {
	var a16 [16]byte
	copy(a16[:], a.AsSlice())
	switch len(a.AsSlice()) {
	case 4:
		return netip.AddrPortFrom(
			netip.AddrFrom4(*(*[4]byte)(a16[:4])).Unmap(),
			port,
		), true
	case 16:
		return netip.AddrPortFrom(netip.AddrFrom16(a16).Unmap(), port), true
	default:
		return ipp, false
	}
}
