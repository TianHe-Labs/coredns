package utils

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
)

func TestNetIp(t *testing.T) {
	s := net.ParseIP("1.2.3.4")
	a, o := netip.AddrFromSlice(s.To4())
	fmt.Println(a, o)
	b, o := netip.AddrFromSlice(s.To16())
	fmt.Println(b, o)
	fmt.Println(a == b)
}

func TestIP(t *testing.T) {
	cases := []struct {
		Name         string
		src, targets []string
		expect       []bool
	}{
		{"group1",
			[]string{"1.2.3.4", "1.2.3.5-1.2.3.8", "1.2.2.0/24",
				"ABCD:EF01:2345:6789:ABCD:EF01:2345:6789",
				"2001:0410:0000:1234:FB00:1400:5000:45FF-2001:0410:0000:1234:FB00:1400:5000:FFFE",
				"2001:0410::FB00:1400:5000:45FF",
				"2001:db8:abcd:0012::0/124"},
			[]string{"1.2.3.4", "1.2.3.7", "1.2.3.9", "1.2.2.1", "1.2.1.1",
				"ABCD:EF01:2345:6789:ABCD:EF01:2345:6789",
				"ABCD:EF01:2345:6789:ABCD:EF01:2345:678A",
				"2001:0410:0000:1234:FB00:1400:5000:4FFF",
				"2001:0410:0000:1234:FB00:1400:5000:FFFF",
				"2001:0410:0:0:FB00:1400:5000:45FF",
				"2001:db8:abcd:0012::1",
				"2001:db8:abcd:0012::1:1234"},
			[]bool{true, true, false, true, false,
				true, false, true, false, true, true, false},
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			s := &IPPool{ips: make(map[netip.Addr]struct{})}
			s.Add(c.src)
			for k, target := range c.targets {
				if res := s.Contain(net.ParseIP(target)); res != c.expect[k] {
					t.Fatalf("ip:%s,expect:%t,res:%t",
						target, c.expect[k], res)
				}
			}
		})
	}
}
