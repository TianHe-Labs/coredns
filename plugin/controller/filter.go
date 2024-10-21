package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/controller/rule"
	"github.com/miekg/dns"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultPolicyId = "00000000-0000-0000-0000-000000000000"

type dnsLog struct {
	RemoteIP string
	Qname    string

	Banned         uint8
	RelatedRuleSet string
	UseCache       uint8

	Qclass   uint16
	Qtype    uint16
	Response string

	ReceiveTimestamp  int64
	ResponseTimestamp int64
}

var logPool = sync.Pool{New: func() interface{} {
	return new(dnsLog)
}}

var msgPool = sync.Pool{New: func() interface{} {
	return new(dns.Msg)
}}

type responseWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (w responseWriter) WriteMsg(res *dns.Msg) error {
	w.msg = res
	return nil
}

type Filter struct {
	Next plugin.Handler
}

func (p *Filter) ServeDNS(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
	var log *dnsLog
	var policy *rule.Policy
	receiveTimestamp := time.Now().UnixNano()
	defer func() {
		if log == nil {
			return
		}
		select {
		case logCh <- log:
		default:
			return
		}
	}()
	atomic.AddUint32(&ReceiveCount, 1)

	// 获取源IP地址
	clientAddr := w.RemoteAddr().String()
	clientIP, _, err := net.SplitHostPort(clientAddr)
	src := net.ParseIP(clientIP)
	if err != nil || src == nil {
		return dns.RcodeServerFailure, err
	}

	// 获取请求的域名
	if len(req.Question) == 0 {
		return dns.RcodeServerFailure, fmt.Errorf("no question in DNS request")
	}

	log = logPool.Get().(*dnsLog)
	log.RemoteIP = clientIP
	log.Qname = strings.ToLower(strings.TrimRight(req.Question[0].Name, "."))
	log.ReceiveTimestamp = receiveTimestamp
	log.Qclass = req.Question[0].Qclass
	log.Qtype = req.Question[0].Qtype
	log.Banned = 0
	log.RelatedRuleSet = "-1"

	policy = GetPolicyIdByIP(src)

	if policy != nil && policy.BannedUserIps != nil && policy.BannedUserIps.Size() > 0 && policy.BannedUserIps.Contain(src) {
		log.Banned = 1
		log.RelatedRuleSet = "banned_user_ip"
		log.UseCache = 0
		return dns.RcodeRefused, fmt.Errorf("banned by user ip")
	}

	if policy != nil && req.Question[0].Qclass == 1 && (req.Question[0].Qtype == dns.TypeA || req.Question[0].Qtype == dns.TypeAAAA) {
		operation, id := policy.Judge(req.Question[0].Name)
		switch operation {
		case rule.OperationForbidden:
			log.Banned = 1
			log.RelatedRuleSet = id
			log.UseCache = 0
			if fakeResponse {
				return FakeResponse(w, req, log)
			} else {
				return dns.RcodeRefused, fmt.Errorf("banned by domain policy")
			}
		}
	}

	// 调用下一个插件处理请求并获取响应
	writer := responseWriter{ResponseWriter: w}
	code, err := plugin.NextOrFailure(p.Name(), p.Next, ctx, writer, req)
	WriteResponseToLog(writer.msg, log)
	if err != nil {
		return code, err
	}
	if code != dns.RcodeSuccess {
		return code, err
	}

	if writer.msg != nil && policy != nil && policy.BannedDnsResolveIps != nil && policy.BannedDnsResolveIps.Size() == 0 {
		for _, answer := range writer.msg.Answer {
			switch answer.(type) {
			case *dns.A:
				if policy.BannedDnsResolveIps.Contain(answer.(*dns.A).A) {
					log.Banned = 1
					log.RelatedRuleSet = "banned_dns_resolve_ip"
					log.UseCache = 0
					if fakeResponse {
						return FakeResponse(w, req, log)
					} else {
						return dns.RcodeRefused, fmt.Errorf("banned by dns resolve ip")
					}

				}
			case *dns.AAAA:
				if policy.BannedDnsResolveIps.Contain(answer.(*dns.AAAA).AAAA) {
					log.Banned = 1
					log.RelatedRuleSet = "banned_dns_resolve_ip"
					log.UseCache = 0
					if fakeResponse {
						return FakeResponse(w, req, log)
					} else {
						return dns.RcodeRefused, fmt.Errorf("banned by dns resolve ip")
					}
				}
			}
		}
	}

	if writer.msg != nil {
		_ = w.WriteMsg(writer.msg)
	}

	return code, err
}

func (p *Filter) Name() string { return "filter" }

func GetPolicyIdByIP(src net.IP) *rule.Policy {
	for id, policy := range rule.Rules.PolicyMap {
		if id == defaultPolicyId {
			continue
		}
		if policy.UserIP != nil && policy.UserIP.Contain(src) {
			return policy
		}
	}
	return rule.Rules.DefaultPolicy
}

func FakeResponse(w dns.ResponseWriter, req *dns.Msg, log *dnsLog) (int, error) {
	msg := msgPool.Get().(*dns.Msg)
	defer msgPool.Put(msg)

	msg.SetReply(req)
	if req.RecursionDesired {
		msg.RecursionAvailable = true
	}

	msg.Answer = []dns.RR{}
	if req.Question[0].Qtype == dns.TypeA {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: req.Question[0].Qtype,
				Class:  req.Question[0].Qclass,
				Ttl:    30,
			},
			A: net.IPv4(127, 0, 0, 1),
		})
	} else if req.Question[0].Qtype == dns.TypeAAAA {
		msg.Answer = append(msg.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: req.Question[0].Qtype,
				Class:  req.Question[0].Qclass,
				Ttl:    30,
			},
			AAAA: net.IPv6loopback,
		})
	}

	b, err := msg.Pack()
	if err == nil {
		log.Response = base64.StdEncoding.EncodeToString(b)
	}

	w.WriteMsg(msg)
	return dns.RcodeSuccess, nil
}

func WriteResponseToLog(msg *dns.Msg, log *dnsLog) {
	if msg != nil {
		b, err := msg.Pack()
		if err == nil {
			log.Response = base64.StdEncoding.EncodeToString(b)
		}
	}
}
