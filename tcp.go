package vmnet

import (
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/exp/slog"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (nt *Network) setTCPForwarder() {
	tcpForwarder := tcp.NewForwarder(
		nt.stack,
		nt.tcpReceiveBufferSize,
		nt.tcpMaxInFlight,
		func(fr *tcp.ForwarderRequest) {
			id := fr.ID()

			// if net.ParseIP(id.LocalAddress.String()).IsPrivate() {
			// 	return
			// }

			addAddress(nt.stack, id.LocalAddress)

			relay := fmt.Sprintf(
				"%s:%d <-> %s:%d",
				id.LocalAddress.String(), id.LocalPort,
				id.RemoteAddress.String(), id.RemotePort,
			)

			var wq waiter.Queue
			ep, tcpipErr := fr.CreateEndpoint(&wq)
			if tcpipErr != nil {
				nt.logger.Info(
					"failed to create TCP end",
					slog.Any("tcpiperr", tcpipErr.String()),
					slog.String("between", relay),
				)
				fr.Complete(true)
				return
			}
			fr.Complete(false)

			ep.SocketOptions().SetKeepAlive(true)

			remoteAddr := fmt.Sprintf("%s:%d", id.LocalAddress, id.LocalPort)
			conn, err := nt.dialTCP(id.LocalAddress, id.LocalPort)
			if err != nil {
				nt.logger.Error(
					"failed to dial TCP", err,
					slog.String("target", remoteAddr),
					slog.String("between", relay),
				)
				return
			}

			nt.logger.Info(
				"start TCP relay",
				slog.String("between", relay),
			)

			err = nt.pool.tcpRelay(conn, gonet.NewTCPConn(&wq, ep))
			if err != nil {
				nt.logger.Error("failed TCP relay", err, slog.String("between", relay))
			}
		},
	)
	nt.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
}

func (nt *Network) dialTCP(addr tcpip.Address, port uint16) (io.ReadWriteCloser, error) {
	if nt.subnet.Contains(addr) {
		return gonet.DialTCP(nt.stack, tcpip.FullAddress{
			NIC:  nicID,
			Addr: addr,
			Port: port,
		}, ipv4.ProtocolNumber)
	}
	remoteAddr := fmt.Sprintf("%s:%d", addr, port)
	conn, err := net.DialTimeout("tcp", remoteAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}
