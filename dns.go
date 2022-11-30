package vmnet

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	cache "github.com/Code-Hex/go-generics-cache"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func (gw *Gateway) serveDNS4Server(laddr *tcpip.FullAddress) error {
	conn, err := dialUDPConn(gw.stack, laddr, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())

	cleanup := func() {
		conn.Close()
		cancel()
	}

	h := &dnsHandler{
		resolver: &dnsResolver{
			c: &dns.Client{
				Net:            "udp",
				DialTimeout:    10 * time.Second,
				ReadTimeout:    30 * time.Second,
				WriteTimeout:   30 * time.Second,
				SingleInflight: true,
			},
			nameservers:   gw.dnsConfig.Nameservers,
			staticRecords: gw.dnsConfig.StaticRecords,
			cache:         cache.NewContext[dns.Question, []dns.RR](ctx),
		},
	}

	go func() {
		defer cleanup()

		rbuf := gw.pool.getBytes()
		defer gw.pool.putBytes(rbuf)

		for {
			n, peer, err := conn.ReadFrom(rbuf)
			if err != nil {
				gw.logger.Error("failed to read from connection in DNS server", err)
				return
			}

			var msg dns.Msg
			if err := msg.Unpack(rbuf[:n]); err != nil {
				gw.logger.Warn("failed parsing DNS request", errAttr(err))
				continue
			}

			upeer, _ := peer.(*net.UDPAddr)

			go func() {
				err := h.handleDNS(conn, &msg, upeer)
				if err != nil {
					gw.logger.Warn("failed to handle DNS request", errAttr(err))
				}
			}()
		}
	}()
	return nil
}

type dnsHandler struct {
	resolver *dnsResolver
}

func (h *dnsHandler) handleDNS(conn net.PacketConn, msg *dns.Msg, peer *net.UDPAddr) error {
	reply := new(dns.Msg)
	reply.SetReply(msg)
	reply.RecursionAvailable = true

	for _, q := range msg.Question {
		rr, err := h.resolver.Lookup(q, msg.MsgHdr, msg.Compress)
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			return err
		}
		if len(rr) > 0 {
			reply.Answer = append(reply.Answer, rr...)
		}
	}

	resp, err := reply.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack DNS reply: %w", err)
	}

	_, err = conn.WriteTo(resp, peer)

	return err
}

type dnsResolver struct {
	c             *dns.Client
	nameservers   []netip.Addr
	staticRecords map[string]netip.Addr
	cache         *cache.Cache[dns.Question, []dns.RR]
}

func (r *dnsResolver) Lookup(q dns.Question, hdr dns.MsgHdr, compress bool) ([]dns.RR, error) {
	if q.Qtype == dns.TypeA {
		// First, Try from static record.
		addr, ok := r.staticRecords[q.Name]
		if ok {
			return []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					A: net.IP(addr.AsSlice()),
				},
			}, nil
		}

		// Second, Try from cache.
		resp, ok := r.cache.Get(q)
		if ok {
			return resp, nil
		}
	}

	// Resolve using dns proxy.
	var eg errgroup.Group
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan *dns.Msg, len(r.nameservers))

	query := &dns.Msg{
		MsgHdr:   hdr,
		Compress: compress,
		Question: []dns.Question{q},
	}

	doFirst := make(chan struct{}, 1)
	doFirst <- struct{}{}

RESOLVE:
	for _, ns := range r.nameservers {
		ns := ns // thread safe

		select {
		case <-ctx.Done():
			break RESOLVE
		case <-doFirst:
		case <-time.After(r.c.DialTimeout):
		}

		eg.Go(func() error {
			target := net.JoinHostPort(ns.String(), "53")
			resp, _, err := r.c.ExchangeContext(ctx, query, target)
			if err != nil {
				return err
			}
			if resp.Rcode == dns.RcodeSuccess {
				ch <- resp
				cancel()
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	resp := <-ch
	if q.Qtype == dns.TypeA {
		minTTL := findDNSARecordMinTTL(resp.Answer)
		if minTTL > 0 {
			exp := time.Duration(minTTL) * time.Second
			r.cache.Set(q, resp.Answer, cache.WithExpiration(exp))
		}
	}
	return resp.Answer, nil
}

func findDNSARecordMinTTL(answers []dns.RR) (minTTL uint32) {
	for _, ans := range answers {
		underlying, ok := ans.(*dns.A)
		if !ok {
			continue
		}
		if minTTL == 0 || minTTL > underlying.Hdr.Ttl {
			minTTL = underlying.Hdr.Ttl
		}
	}
	return
}

// DNSConfig is a configuration to resolve DNS in the guest OS.
type DNSConfig struct {
	// Nameservers are the IP addresses of the nameservers to use.
	// If empty, use values from resolv.conf.
	Nameservers []netip.Addr

	// SearchDomains are the domain suffixes to use when expanding
	// single-label name queries.
	// If empty, use values from resolv.conf.
	SearchDomains []string

	// StaticRecords are the DNS records will be served by the DNS
	// server embedded in the gateway if this value is not empty.
	//
	// If this is not empty, the gateway IP is automatically appended
	// to Nameservers.
	StaticRecords map[string]netip.Addr
}

// resolvConfPath is the canonical location of resolv.conf.
const resolvConfPath = "/etc/resolv.conf"

// 1.1.1.1 is a public DNS resolver that makes DNS queries
// faster and more secure.
//
// https://www.cloudflare.com/learning/dns/what-is-1.1.1.1/
const fallbackNameserver = "1.1.1.1"

func parseResolvConf(r io.Reader) (*DNSConfig, error) {
	config := new(DNSConfig)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		noCommentLine, _, _ := strings.Cut(line, "#")

		const nameserver = "nameserver"
		if strings.HasPrefix(noCommentLine, nameserver) {
			// i.e. "nameserver 192.168.11.1"
			ns := strings.TrimSpace(noCommentLine[len(nameserver):])
			addr, err := netip.ParseAddr(ns)
			if err != nil {
				return nil, fmt.Errorf("parse error in %q: %w", line, err)
			}
			if addr.Is4() {
				config.Nameservers = append(config.Nameservers, addr)
			}
			continue
		}

		const search = "search"
		if strings.HasPrefix(line, search) {
			// i.e. "search vlan"
			fqdn := strings.TrimSpace(noCommentLine[len(search):])
			config.SearchDomains = append(config.SearchDomains, dns.Fqdn(fqdn))
			continue
		}
	}

	if len(config.Nameservers) == 0 {
		fallbackAddr := netip.MustParseAddr(fallbackNameserver)
		config.Nameservers = append(config.Nameservers, fallbackAddr)
	}
	return config, nil
}

// parseResolvConfFile parses the named resolv.conf file.
func parseResolvConfFile(name string) (*DNSConfig, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseResolvConf(f)
}
