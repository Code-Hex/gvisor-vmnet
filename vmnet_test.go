package vmnet_test

import (
	"net"
	"net/netip"
	"testing"

	vmnet "github.com/Code-Hex/gvisor-vmnet"
	"github.com/google/go-cmp/cmp"
)

func TestGateway_LeaseIP(t *testing.T) {
	gwHwAddr := net.HardwareAddr{
		0x7a, 0x5b, 0x10, 0x21, 0x90, 0xe3,
	}

	tests := []struct {
		cidr         string
		wantLen      int
		wantFromHead []vmnet.DHCPLease
		wantErr      bool
	}{
		{
			cidr:    "192.168.127.0/24",
			wantLen: 254,
			wantFromHead: []vmnet.DHCPLease{
				{
					HardwareAddr: gwHwAddr,
					Addr:         netip.MustParseAddr("192.168.127.1"),
				},
				{
					Addr: netip.MustParseAddr("192.168.127.2"),
				},
				{
					Addr: netip.MustParseAddr("192.168.127.3"),
				},
			},
		},
		{
			cidr:    "192.168.128.0/28",
			wantLen: 14,
			wantFromHead: []vmnet.DHCPLease{
				{
					HardwareAddr: gwHwAddr,
					Addr:         netip.MustParseAddr("192.168.128.1"),
				},
				{
					Addr: netip.MustParseAddr("192.168.128.2"),
				},
				{
					Addr: netip.MustParseAddr("192.168.128.3"),
				},
			},
		},
		{
			cidr:    "192.168.129.0/30",
			wantLen: 2,
			wantFromHead: []vmnet.DHCPLease{
				{
					HardwareAddr: gwHwAddr,
					Addr:         netip.MustParseAddr("192.168.129.1"),
				},
				{
					Addr: netip.MustParseAddr("192.168.129.2"),
				},
			},
		},
		{
			cidr:    "192.168.130.0/31",
			wantErr: true,
		},
		{
			cidr:    "192.168.130.0/32",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			gw, err := vmnet.NewGateway(tt.cidr, vmnet.WithMACAddress(gwHwAddr))
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			got := gw.LeaseIP()
			if len(got) != tt.wantLen {
				t.Fatalf("want len %d but got %d", tt.wantLen, len(got))
			}
			if diff := cmp.Diff(
				tt.wantFromHead,
				got[:len(tt.wantFromHead)],
				cmp.Comparer(func(x, y netip.Addr) bool {
					return x.Compare(y) == 0
				}),
			); diff != "" {
				t.Errorf("(-want, +got)\n%s", diff)
			}
		})
	}
}
