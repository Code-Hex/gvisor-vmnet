package vmnet

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (gw *Gateway) serveDHCP4Server(s *stack.Stack, subnetMask net.IPMask, laddr *tcpip.FullAddress) error {
	conn, err := dialUDPConn(s, laddr, ipv4.ProtocolNumber, func(so *tcpip.SocketOptions) {
		so.SetBroadcast(true)
	})
	if err != nil {
		return err
	}

	h := &dhcpHandler{
		gatewayIP:     gw.ipv4,
		subnetMask:    subnetMask,
		leaseDB:       gw.leaseDB,
		searchDomains: gw.dnsConfig.SearchDomains,
	}

	go func() {
		defer conn.Close()

		rbuf := gw.pool.getBytes()
		defer gw.pool.putBytes(rbuf)

		for {
			n, peer, err := conn.ReadFrom(rbuf)
			if err != nil {
				gw.logger.Error("failed to read from connection in DHCPv4 server", err)
				return
			}

			m, err := dhcpv4.FromBytes(rbuf[:n])
			if err != nil {
				gw.logger.Warn("failed parsing DHCPv4 request", errAttr(err))
				continue
			}

			go func() {
				err := h.handlerv4(conn, peer.(*net.UDPAddr), m)
				if err != nil {
					gw.logger.Warn("failed to handle DHCPv4 request", errAttr(err))
				}
			}()
		}
	}()
	return nil
}

type dhcpHandler struct {
	gatewayIP     net.IP
	subnetMask    net.IPMask
	leaseDB       *leaseDB
	searchDomains []string
}

func (h *dhcpHandler) handlerv4(conn net.PacketConn, peer *net.UDPAddr, msg *dhcpv4.DHCPv4) error {
	yourIP, err := h.leaseDB.LeaseIP(msg.ClientHWAddr)
	if err != nil {
		return err
	}

	modifiers := []dhcpv4.Modifier{
		dhcpv4.WithReply(msg),
		dhcpv4.WithRouter(h.gatewayIP), // the default route
		dhcpv4.WithServerIP(h.gatewayIP),
		dhcpv4.WithDNS(h.gatewayIP),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(h.gatewayIP)),
		dhcpv4.WithYourIP(yourIP),
		dhcpv4.WithLeaseTime(3600), // hour works
		dhcpv4.WithNetmask(h.subnetMask),
		dhcpv4.WithDomainSearchList(h.searchDomains...),
	}

	switch msg.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		modifiers = append(modifiers, dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer))
	case dhcpv4.MessageTypeRequest:
		modifiers = append(modifiers, dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
	}

	dhcpReply, err := dhcpv4.New(modifiers...)
	if err != nil {
		return fmt.Errorf("failed to build DHCPv4 reply message: %w", err)
	}

	// Set peer to broadcast if the client did not have an IP.
	if peer.IP == nil || peer.IP.To4().Equal(net.IPv4zero) {
		peer = &net.UDPAddr{
			IP:   net.IPv4bcast,
			Port: peer.Port,
		}
	}

	if _, err := conn.WriteTo(dhcpReply.ToBytes(), peer); err != nil {
		return fmt.Errorf("dhcpv4 server reply failed: %w", err)
	}
	return nil
}

type leaseDB struct {
	leases       []*lease
	leasePointer map[string]*lease // key is net.HardwareAddr.String()
	mu           sync.RWMutex
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
	db.mu.RLock()
	l, ok := db.leasePointer[hwAddr.String()]
	db.mu.RUnlock()
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
	if len(ips) < 2 {
		return []netip.Addr{}, nil
	}

	return ips[1 : len(ips)-1], nil
}
