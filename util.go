package vmnet

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func netaddrIPFromNetstackIP(s tcpip.Address) netip.Addr {
	switch len(s) {
	case 4:
		return netip.AddrFrom4([4]byte{s[0], s[1], s[2], s[3]})
	case 16:
		var a [16]byte
		copy(a[:], s)
		return netip.AddrFrom16(a).Unmap()
	}
	return netip.Addr{}
}

func ipPortOfNetstackAddr(a tcpip.Address, port uint16) (ipp netip.AddrPort, ok bool) {
	var a16 [16]byte
	copy(a16[:], a)
	switch len(a) {
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
