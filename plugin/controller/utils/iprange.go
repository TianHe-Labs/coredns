package utils

import (
	"fmt"
	"github.com/netdata/go.d.plugin/pkg/iprange"
	"net"
	"net/netip"
	"strings"
)

type IPPool struct {
	ips    map[netip.Addr]struct{}
	ranges []iprange.Range
	size   int
	Hash   string
}

func NewIPPool() *IPPool {
	return &IPPool{ips: map[netip.Addr]struct{}{}}
}

func (s *IPPool) Add(items []string) error {
	for _, item := range items {
		if item == "" {
			continue
		}
		if strings.Contains(item, "-") || strings.Contains(item, "/") {
			r, err := iprange.ParseRange(item)
			if err != nil {
				return err
			}
			s.ranges = append(s.ranges, r)
		} else {
			ip, ok := netip.AddrFromSlice(net.ParseIP(item))
			if !ok {
				return fmt.Errorf("error in parsing %s", item)
			}
			s.ips[ip] = struct{}{}
		}
		s.size++
	}
	return nil
}

func (s *IPPool) Size() int {
	return s.size
}

func (s *IPPool) Contain(ip net.IP) (has bool) {
	ip = ip.To16()
	addr, _ := netip.AddrFromSlice(ip)
	_, has = s.ips[addr]
	if !has {
		for i := range s.ranges {
			if s.ranges[i].Contains(ip) {
				return true
			}
		}
	}
	return
}
