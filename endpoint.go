package vmnet

import (
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/exp/slog"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type endpoint struct {
	// conn is the set of connection each identifying one inbound/outbound
	// channel.
	conns map[tcpip.Address]net.Conn

	connmu sync.RWMutex

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// addr is the MAC address of the endpoint.
	addr tcpip.LinkAddress

	dispatcher stack.NetworkDispatcher

	// wg keeps track of running goroutines.
	wg sync.WaitGroup

	// closed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	closed func(tcpip.Address, error)

	writer *pcapgo.Writer

	pool *bytePool

	logger *slog.Logger
}

type gatewayEndpointOption struct {
	MTU        uint32
	Address    tcpip.LinkAddress
	Writer     *os.File
	ClosedFunc func(tcpip.Address, error)
	Pool       *bytePool
	Logger     *slog.Logger
}

func newGatewayEndpoint(opts gatewayEndpointOption) (*endpoint, error) {
	ep := &endpoint{
		conns:  map[tcpip.Address]net.Conn{},
		mtu:    opts.MTU,
		closed: opts.ClosedFunc,
		addr:   opts.Address,
		pool:   opts.Pool,
		logger: opts.Logger,
	}
	if opts.Writer != nil {
		log.Println(opts.Writer)
		ep.writer = pcapgo.NewWriter(opts.Writer)
		if err := ep.writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
			return nil, err
		}
	}
	return ep, nil
}

func (e *endpoint) RegisterConn(devAddr tcpip.Address, conn net.Conn) {
	e.connmu.Lock()
	e.conns[devAddr] = conn
	e.connmu.Unlock()

	// Link endpoints are not savable. When transportation endpoints are
	// saved, they stop sending outgoing packets and all incoming packets
	// are rejected.
	if e.dispatcher != nil {
		e.wg.Add(1)
		go func() {
			e.dispatchLoop(devAddr, conn)
			e.wg.Done()
		}()
	}
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityResolutionRequired
}

// MaxHeaderLength returns the maximum size of the link-layer header.
func (e *endpoint) MaxHeaderLength() uint16 {
	return header.EthernetMinimumSize
}

// LinkAddress returns the link address of this endpoint.
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// Wait implements stack.LinkEndpoint.Wait. It waits for the endpoint to stop
// reading from its FD.
func (e *endpoint) Wait() {
	e.wg.Wait()
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *endpoint) AddHeader(pkt *stack.PacketBuffer) {
	// Add ethernet header if needed.
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		SrcAddr: pkt.EgressRoute.LocalLinkAddress,
		DstAddr: pkt.EgressRoute.RemoteLinkAddress,
		Type:    pkt.NetworkProtocolNumber,
	})
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher. If one is already attached,
// then nothing happens.
//
// Attach implements stack.LinkEndpoint.Attach.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	// nil means the NIC is being removed.
	if dispatcher == nil && e.dispatcher != nil {
		e.Wait()
		e.dispatcher = nil
		return
	}
	if dispatcher != nil && e.dispatcher == nil {
		e.dispatcher = dispatcher
	}
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop(devAddr tcpip.Address, conn net.Conn) {
	for {
		cont, err := e.inboundDispatch(conn)
		if err != nil || !cont {

			e.connmu.Lock()
			delete(e.conns, devAddr)
			e.connmu.Unlock()

			if e.closed != nil {
				e.closed(devAddr, err)
			}
			return
		}
	}
}

// writePacket writes outbound packets to the connection. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	data := pkt.ToView().AsSlice()

	if e.writer != nil {
		e.writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(data),
			Length:        len(data),
		}, data)
	}

	e.connmu.RLock()
	conn, ok := e.conns[pkt.EgressRoute.RemoteAddress]
	e.connmu.RUnlock()
	if ok {
		if _, err := conn.Write(data); err != nil {
			e.logger.Warn("failed to write packet data in endpoint", errAttr(err))
			return &tcpip.ErrInvalidEndpointState{}
		}
		return nil
	}

	e.connmu.RLock()
	defer e.connmu.RUnlock()
	for _, conn := range e.conns {
		conn.Write(data)
	}
	return nil
}

// WritePackets writes outbound packets to the underlying connection. If
// one is not currently writable, the packet is dropped.
//
// Being a batch API, each packet in pkts should have the following
// fields populated:
//   - pkt.EgressRoute
//   - pkt.NetworkProtocolNumber
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (written int, err tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		if err := e.writePacket(pkt); err != nil {
			break
		}
		written++
	}
	return written, err
}

// dispatch reads one packet from the file descriptor and dispatches it.
func (e *endpoint) inboundDispatch(conn net.Conn) (bool, error) {
	data := e.pool.getBytes()
	defer e.pool.putBytes(data)

	n, err := conn.Read(data)
	if err != nil {
		return false, err
	}

	if e.writer != nil {
		e.writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: n,
			Length:        n,
		}, data[:n])
	}

	buf := bufferv2.MakeWithData(data[:n])
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buf,
	})
	defer pkt.DecRef()

	return e.deliverOrConsumeNetworkPacket(pkt, conn)
}

func (e *endpoint) deliverOrConsumeNetworkPacket(
	pkt *stack.PacketBuffer,
	conn net.Conn,
) (bool, error) {
	hdr, ok := pkt.LinkHeader().Consume(int(e.MaxHeaderLength()))
	if !ok {
		return false, nil
	}
	ethHdr := header.Ethernet(hdr)

	data := pkt.ToView().AsSlice()

	if ethHdr.Type() != ipv4.ProtocolNumber {
		e.dispatcher.DeliverNetworkPacket(ethHdr.Type(), pkt)
		return true, nil
	}

	ipv4 := header.IPv4(data[header.EthernetMinimumSize:])

	switch ipv4.TransportProtocol() {
	case header.ICMPv4ProtocolNumber:
		{
			icmpv4 := header.ICMPv4(data[header.EthernetMinimumSize+header.IPv4MinimumSize:])
			// Only ICMPv4 echo request is emulated on the Go side.
			//
			// sudo privilege is required to use ICMP packets. So gvisor
			// cannot use ICMPv4 packets as they are. Therefore, gvisor
			// looks at the contents of the packets and converts them to
			// echo requests using UDP. The result is converted to ICMPv4
			// packet, which is then passed to the guest.
			//
			// TODO(codehex): add handling for subnet to pass deliver network.
			if icmpv4.Type() == header.ICMPv4Echo {
				tmp := icmpv4.Payload()
				payload := make([]byte, len(tmp))
				copy(payload, tmp)

				go pingv4(conn, pingPacket{
					srcIP:    ipv4.SourceAddress(),
					dstIP:    ipv4.DestinationAddress(),
					srcMAC:   ethHdr.SourceAddress(),
					dstMAC:   ethHdr.DestinationAddress(),
					payload:  payload,
					ident:    icmpv4.Ident(),
					sequence: icmpv4.Sequence(),
				})
				return true, nil
			}
		}
	default:
	}

	e.dispatcher.DeliverNetworkPacket(ethHdr.Type(), pkt)

	return true, nil
}
