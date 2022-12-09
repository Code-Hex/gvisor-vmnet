package vmnet

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type dhcpHandler struct {
	gatewayIP     net.IP
	subnetMask    net.IPMask
	leaseDB       *leaseDB
	searchDomains []string
}

type dhcpv4Packet struct {
	srcIP, dstIP     tcpip.Address
	srcPort, dstPort uint16
	srcMAC, dstMAC   tcpip.LinkAddress
	msg              *dhcpv4.DHCPv4
}

func (h *dhcpHandler) handleDHCPv4(conn io.Writer, p dhcpv4Packet) error {
	yourIP, err := h.leaseDB.LeaseIP(p.msg.ClientHWAddr)
	if err != nil {
		return err
	}

	modifiers := []dhcpv4.Modifier{
		dhcpv4.WithReply(p.msg),
		dhcpv4.WithRouter(h.gatewayIP), // the default route
		dhcpv4.WithServerIP(h.gatewayIP),
		dhcpv4.WithDNS(h.gatewayIP),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(h.gatewayIP)),
		dhcpv4.WithYourIP(yourIP),
		dhcpv4.WithLeaseTime(3600), // hour works
		dhcpv4.WithNetmask(h.subnetMask),
		dhcpv4.WithDomainSearchList(h.searchDomains...),
	}

	switch p.msg.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		modifiers = append(modifiers, dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer))
	case dhcpv4.MessageTypeRequest:
		modifiers = append(modifiers, dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
	}

	dhcpReply, err := dhcpv4.New(modifiers...)
	if err != nil {
		return fmt.Errorf("failed to build DHCPv4 reply message: %w", err)
	}

	packet := makeUDPv4Packet(
		p.dstMAC,
		p.srcMAC,
		tcpip.Address(h.gatewayIP),
		tcpip.Address(net.IPv4bcast),
		p.dstPort,
		p.srcPort,
		dhcpReply.ToBytes(),
	)

	_, err = conn.Write(packet)

	return err
}

// makeUDPv4Packet returns an UDP IPv4 packet.
func makeUDPv4Packet(
	srcMAC, dstMAC tcpip.LinkAddress,
	srcIP, dstIP tcpip.Address,
	srcPort, dstPort uint16,
	payload []byte,
) []byte {
	const ethernetUDPv4MinimumSize = header.EthernetMinimumSize + header.IPv4MinimumSize + header.UDPMinimumSize
	buf := make([]byte, ethernetUDPv4MinimumSize+len(payload))

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
		TTL:         65,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     srcIP,
		DstAddr:     dstIP,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// UDP header
	udpv4buf := buf[header.EthernetMinimumSize+header.IPv4MinimumSize:]
	udpv4 := header.UDP(udpv4buf)
	udpv4.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(udpv4.Payload(), payload)
	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, srcIP, dstIP, uint16(len(udpv4)))
	// Calculate the UDP checksum and set it.
	xsum = header.Checksum(payload, xsum)
	udpv4.SetChecksum(^udpv4.CalculateChecksum(xsum))

	return buf
}

type leaseDB struct {
	leases       []*lease
	leasePointer map[string]*lease // key is net.HardwareAddr.String()
	mu           sync.Mutex
}

type lease struct {
	hwAddr net.HardwareAddr
	ipAddr netip.Addr
}

func newLeaseDB(cidr string) (*leaseDB, error) {
	ipAddrs, err := hosts(cidr)
	if err != nil {
		return nil, err
	}
	if len(ipAddrs) < 2 {
		// 1. for gateway
		// 2. for VM
		return nil, fmt.Errorf("at least two IP addresses are required")
	}

	leases := make([]*lease, len(ipAddrs))
	for i, ipAddr := range ipAddrs {
		leases[i] = &lease{
			ipAddr: ipAddr,
		}
	}

	return &leaseDB{
		leases:       leases,
		leasePointer: make(map[string]*lease),
	}, nil
}

// LeaseIP leases IP address to specified MAC address of the device. If already leased
// for the specified MAC address, returns the IP address.
func (db *leaseDB) LeaseIP(hwAddr net.HardwareAddr) (net.IP, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	l, ok := db.leasePointer[hwAddr.String()]
	if ok {
		return l.ipAddr.AsSlice(), nil
	}

	for i := 0; i < len(db.leases); i++ {
		l := db.leases[i]
		if l.hwAddr == nil {
			l.hwAddr = hwAddr
			db.leasePointer[hwAddr.String()] = l
			return l.ipAddr.AsSlice(), nil
		}
	}
	return nil, fmt.Errorf("IP addresses are unavailable")
}

func (db *leaseDB) getLeases() []*lease {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.leases
}

func hosts(cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr)
	}

	// Returns ips with excluded "192.168.127.0" and "192.168.127.255" if specified "192.168.127.0/24"
	// https://superuser.com/questions/1111437/why-cant-i-use-the-first-or-last-address-in-a-subnet
	if len(ips) < 2 {
		return []netip.Addr{}, nil
	}

	return ips[1 : len(ips)-1], nil
}
