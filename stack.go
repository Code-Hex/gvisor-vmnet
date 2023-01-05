package vmnet

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID = 1

func createBaseNetStack() (*stack.Stack, error) {
	netProtos := []stack.NetworkProtocolFactory{
		ipv4.NewProtocol,
		// ipv6.NewProtocol,
		arp.NewProtocol,
	}
	transProtos := []stack.TransportProtocolFactory{
		tcp.NewProtocol,
		udp.NewProtocol,
		icmp.NewProtocol4,
		// icmp.NewProtocol6,
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   netProtos,
		TransportProtocols: transProtos,
	})

	transOpts := []struct {
		name string
		f    func(*stack.Stack) tcpip.Error
	}{
		{
			name: "Enable SACK",
			f: func(s *stack.Stack) tcpip.Error {
				opt := tcpip.TCPSACKEnabled(true)
				return s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
			},
		},
		// {
		// 	name: "Set reno congestion control",
		// 	f: func(s *stack.Stack) tcpip.Error {
		// 		opt := tcpip.CongestionControlOption("cubic") // "reno" or "cubic"
		// 		return s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
		// 	},
		// },
		// {
		// 	// https://gvisor.dev/blog/2021/08/31/gvisor-rack/
		// 	name: "Enable RACK Recovery",
		// 	f: func(s *stack.Stack) tcpip.Error {
		// 		opt := tcpip.TCPRACKLossDetection
		// 		return s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
		// 	},
		// },
		// {
		// 	name: "Disable TCP Delay",
		// 	f: func(s *stack.Stack) tcpip.Error {
		// 		opt := tcpip.TCPDelayEnabled(false)
		// 		return s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
		// 	},
		// },
		{
			name: "Enable Receive Buffer Auto-Tuning",
			f: func(s *stack.Stack) tcpip.Error {
				opt := tcpip.TCPModerateReceiveBufferOption(true)
				return s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
			},
		},
		{
			name: "Set TCP Send Buffer Size Range",
			f: func(s *stack.Stack) tcpip.Error {
				return s.SetTransportProtocolOption(tcp.ProtocolNumber,
					&tcpip.TCPSendBufferSizeRangeOption{
						Min:     tcp.MinBufferSize,
						Default: tcp.DefaultSendBufferSize,
						Max:     tcp.MaxBufferSize,
					})
			},
		},
		{
			name: "Set TCP Receive Buffer Size Range",
			f: func(s *stack.Stack) tcpip.Error {
				return s.SetTransportProtocolOption(tcp.ProtocolNumber,
					&tcpip.TCPReceiveBufferSizeRangeOption{
						Min:     tcp.MinBufferSize,
						Default: tcp.DefaultReceiveBufferSize,
						Max:     tcp.MaxBufferSize,
					})
			},
		},
	}
	for _, transOpt := range transOpts {
		if err := transOpt.f(s); err != nil {
			return nil, fmt.Errorf("%s: %v", transOpt.name, err)
		}
	}

	opt := tcpip.DefaultTTLOption(65)
	if err := s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt); err != nil {
		return nil, fmt.Errorf("SetNetworkProtocolOption(%d, &%T(%d)): %s", ipv4.ProtocolNumber, opt, opt, err)
	}

	return s, nil
}

// used in TCP, UDP relay
func addAddress(s *stack.Stack, ip tcpip.Address) error {
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: ip.WithPrefix(),
	}
	tcpipErr := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{
		PEB:        stack.CanBePrimaryEndpoint,
		ConfigType: stack.AddressConfigStatic,
	})
	if tcpipErr != nil {
		return fmt.Errorf("failed to add protocol address (%v): %v", ip, tcpipErr)
	}
	return nil
}
