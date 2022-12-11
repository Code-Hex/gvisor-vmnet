package vmnet

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/exp/slog"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (nt *Network) setUDPForwarder() {
	udpForwarder := udp.NewForwarder(nt.stack, func(fr *udp.ForwarderRequest) {
		id := fr.ID()

		addAddress(nt.stack, id.LocalAddress)

		relay := fmt.Sprintf(
			"%s:%d <-> %s:%d",
			id.LocalAddress.String(), id.LocalPort,
			id.RemoteAddress.String(), id.RemotePort,
		)
		nt.logger.Info(
			"start UDP relay",
			slog.String("between", relay),
		)

		var wq waiter.Queue
		ep, tcpipErr := fr.CreateEndpoint(&wq)
		if tcpipErr != nil {
			nt.logger.Info(
				"failed to create TCP end",
				slog.Any("tcpiperr", tcpipErr.String()),
				slog.String("between", relay),
			)
			return
		}

		clientAddr := &net.UDPAddr{
			IP:   net.IP([]byte(id.RemoteAddress)),
			Port: int(id.RemotePort),
		}
		remoteAddr := &net.UDPAddr{
			IP:   net.IP([]byte(id.LocalAddress)),
			Port: int(id.LocalPort),
		}

		proxyConn, err := nt.listenUDP(id.LocalAddress, id.LocalPort)
		if err != nil {
			if err != nil {
				nt.logger.Warn(
					"failed to bind local port",
					errAttr(err),
					slog.String("between", relay),
				)
				return
			}
		}

		client := gonet.NewUDPConn(nt.stack, &wq, ep)

		ctx := slog.NewContext(context.Background(), nt.logger)
		ctx, cancel := context.WithCancel(ctx)

		idleTimeout := time.Minute
		timer := time.AfterFunc(idleTimeout, func() {
			cancel()
		})
		go func() {
			<-ctx.Done()
			client.Close()
			proxyConn.Close()
		}()

		extend := func() { timer.Reset(idleTimeout) }

		go func() {
			defer cancel()
			nt.pool.udpRelay(ctx, client, clientAddr, proxyConn, cancel, extend) // loc <- remote
		}()
		go func() {
			defer cancel()
			nt.pool.udpRelay(ctx, proxyConn, remoteAddr, client, cancel, extend) // remote <- loc
		}()
	})
	nt.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
}

func (nt *Network) listenUDP(addr tcpip.Address, port uint16) (net.PacketConn, error) {
	proxyAddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(port),
	}
	if nt.subnet.Contains(addr) {
		return gonet.DialUDP(nt.stack, &tcpip.FullAddress{
			Addr: tcpip.Address(net.IPv4zero),
			Port: 0, // random port
		}, nil, ipv4.ProtocolNumber)
	}
	proxyConn, err := net.ListenUDP("udp", proxyAddr)
	if err != nil {
		proxyAddr.Port = 0
		proxyConn, err = net.ListenUDP("udp", proxyAddr)
		if err != nil {
			return nil, err
		}
	}
	return proxyConn, err
}

func dialUDPConn(
	s *stack.Stack,
	laddr *tcpip.FullAddress,
	network tcpip.NetworkProtocolNumber,
	opts ...func(*tcpip.SocketOptions),
) (*gonet.UDPConn, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(udp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, fmt.Errorf(err.String())
	}

	for _, opt := range opts {
		opt(ep.SocketOptions())
	}

	if err := ep.Bind(*laddr); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "bind",
			Net:  "udp",
			Addr: fullToUDPAddr(*laddr),
			Err:  fmt.Errorf(err.String()),
		}
	}

	return gonet.NewUDPConn(s, &wq, ep), nil
}

func fullToUDPAddr(addr tcpip.FullAddress) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IP(addr.Addr), Port: int(addr.Port)}
}
