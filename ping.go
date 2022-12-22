package vmnet

import (
	"fmt"
	"io"
	"net"

	xicmp "golang.org/x/net/icmp"
	xipv4 "golang.org/x/net/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

type pingPacket struct {
	srcIP, dstIP    tcpip.Address
	srcMAC, dstMAC  tcpip.LinkAddress
	payload         []byte
	ident, sequence uint16
}

func pingv4(conn io.Writer, p pingPacket) {
	ttl, err := pingv4Echo(
		p.dstIP,
		p.payload,
		p.ident,
		p.sequence,
	)
	if err != nil {
		return
	}

	packet := makeICMPv4EchoPacket(
		p.dstIP,
		p.srcIP,
		p.dstMAC,
		p.srcMAC,
		uint8(ttl),
		header.ICMPv4EchoReply,
		p.payload,
		p.ident,
		p.sequence,
	)
	conn.Write(packet)
}

func pingv4Echo(
	dst tcpip.Address,
	payload []byte,
	ident, sequence uint16,
) (uint8, error) {
	c, err := xicmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return 0, err
	}

	wm := xicmp.Message{
		Type: xipv4.ICMPTypeEcho,
		Code: 0,
		Body: &xicmp.Echo{
			ID:   int(ident),
			Seq:  int(sequence),
			Data: payload,
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return 0, err
	}
	if _, err := c.WriteTo(wb, &net.UDPAddr{IP: net.ParseIP(dst.String())}); err != nil {
		return 0, err
	}

	cc := c.IPv4PacketConn()
	if err := cc.SetControlMessage(xipv4.FlagTTL, true); err != nil {
		return 0, err
	}

	// Use nil because there is no required payload.
	_, cm, _, err := cc.ReadFrom(nil)
	if err != nil {
		return 0, err
	}
	if cm == nil {
		return 0, fmt.Errorf("no ttl")
	}
	return uint8(cm.TTL), nil
}

// makeICMPv4EchoPacket returns an ICMPv4 echo packet.
func makeICMPv4EchoPacket(
	srcIP, dstIP tcpip.Address,
	srcMAC, dstMAC tcpip.LinkAddress,
	ttl uint8,
	ty header.ICMPv4Type,
	payload []byte,
	ident, sequence uint16,
) []byte {
	const ethernetICMPv4MinimumSize = header.EthernetMinimumSize + header.IPv4MinimumSize + header.ICMPv4MinimumSize
	buf := make([]byte, ethernetICMPv4MinimumSize+len(payload))

	// Ethernet header
	eth := header.Ethernet(buf)
	eth.Encode(&header.EthernetFields{
		SrcAddr: srcMAC,
		DstAddr: dstMAC,
		Type:    ipv4.ProtocolNumber,
	})

	// IP header
	ipbuf := buf[header.EthernetMinimumSize:]
	ip := header.IPv4(ipbuf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(ipbuf)),
		TTL:         ttl,
		Protocol:    uint8(icmp.ProtocolNumber4),
		SrcAddr:     srcIP,
		DstAddr:     dstIP,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// ICMPv4 header
	icmpv4buf := buf[header.EthernetMinimumSize+header.IPv4MinimumSize:]
	icmpv4 := header.ICMPv4(icmpv4buf)
	icmpv4.SetType(ty)
	icmpv4.SetCode(header.ICMPv4UnusedCode)
	icmpv4.SetIdent(ident)
	icmpv4.SetSequence(sequence)
	copy(icmpv4.Payload(), payload)
	icmpv4.SetChecksum(0)
	icmpv4.SetChecksum(^checksum.Checksum(icmpv4, 0))

	return buf
}
