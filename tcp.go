package vmnet

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/exp/slog"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (n *Network) setTCPForwarder() {
	tcpForwarder := tcp.NewForwarder(
		n.stack,
		n.tcpReceiveBufferSize,
		n.tcpMaxInFlight,
		func(fr *tcp.ForwarderRequest) {
			id := fr.ID()

			// if net.ParseIP(id.LocalAddress.String()).IsPrivate() {
			// 	return
			// }

			addAddress(n.stack, id.LocalAddress)

			relay := fmt.Sprintf(
				"%s:%d <-> %s:%d",
				id.LocalAddress.String(), id.LocalPort,
				id.RemoteAddress.String(), id.RemotePort,
			)

			var wq waiter.Queue
			ep, tcpipErr := fr.CreateEndpoint(&wq)
			if tcpipErr != nil {
				n.logger.Info(
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
			conn, err := net.DialTimeout("tcp", remoteAddr, 5*time.Second)
			if err != nil {
				n.logger.Error(
					"failed to dial TCP", err,
					slog.String("target", remoteAddr),
					slog.String("between", relay),
				)
				return
			}

			n.logger.Info(
				"start TCP relay",
				slog.String("between", relay),
			)

			err = n.pool.tcpRelay(conn, gonet.NewTCPConn(&wq, ep))
			if err != nil {
				n.logger.Error("failed TCP relay", err, slog.String("between", relay))
			}
		},
	)
	n.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
}
