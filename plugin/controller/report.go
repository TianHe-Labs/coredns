package controller

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	ec "github.com/coredns/coredns/plugin/controller/error"
	"github.com/coredns/coredns/plugin/controller/rule"
	"github.com/coredns/coredns/plugin/controller/utils"
	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/plugin/forward"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/miekg/dns"
	"github.com/netdata/go.d.plugin/pkg/iprange"
	"github.com/tidwall/gjson"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var apiUrl string
var deviceId string

var syncSignal = make(chan bool, 1)
var client = http.Client{Timeout: time.Second * 5, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
var reportInterval = time.Second * 10
var fileCache = make(map[string][]byte)

func init() {
	syncSignal <- true
}

type SyncData struct {
	LastUpdateTimestamp int64             `json:"last_update_timestamp"`
	DeviceGroup         map[string]string `json:"segmentgroup"`
	Ruleset             map[string]string `json:"ruleset"`
	Policy              map[string]string `json:"policy"`
	BannedUserIps       map[string]string `json:"banned_user_ips"`
	BannedDnsResolveIps map[string]string `json:"banned_dns_resolve_ips"`
	Config              config            `json:"config"`
	Zone                map[string]string `json:"zone"`
}

type config struct {
	DefaultDnsServers   []string            `json:"default_dns_servers"`
	SpecifiedDnsServers map[string][]string `json:"specified_dns_servers"`
}

type ReportStatus struct {
	Id                  string     `json:"id"`
	Status              string     `json:"status"`
	LastUpdateTimestamp int64      `json:"last_update_timestamp"`
	ErrorMessages       string     `json:"error_messages"`
	Statistics          Statistics `json:"statistics"`
}

func Reporter() {
	time.Sleep(time.Second)
	for {
		go func() {
			err := Report()
			if err != nil {
				fmt.Println("error in report: ", err)
			}
		}()
		time.Sleep(reportInterval)
	}
}

func Report() (err error) {
	reportStatus := BuildReportStatus()
	defer func() {
		if reportStatus.Status == "running" {
			syncSignal <- true
		}
		if e := recover(); e != nil {
			err = fmt.Errorf("%s", e)
		}
	}()

	b, _ := json.Marshal(reportStatus)
	resp, err := client.Post(apiUrl+"/api/dns/report", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	j := gjson.ParseBytes(b)
	if resp.StatusCode != 200 || j.Get("code").Int() != 200 || !j.Get("data").Exists() {
		ec.ErrCollector.New("policy", "error in parsing report response [basic]: "+string(b))
		return err
	}
	if reportStatus.Status != "running" {
		return nil
	}
	data := &SyncData{}
	err = json.Unmarshal([]byte(j.Get("data").String()), data)
	if err != nil {
		ec.ErrCollector.New("policy", "error in unmarshal response data: "+string(b))
		return err
	}

	if data.LastUpdateTimestamp == rule.Rules.LastUpdateTimestamp {
		return nil
	}
	ec.ErrCollector.Cache.PolicyError = []ec.Error{}
	ec.ErrCollector.Cache.ConfigError = []ec.Error{}

	UpdateConfig(data.Config)
	if err = UpdateZone(data.Zone); err != nil {
		ec.ErrCollector.New("config", fmt.Sprintf("error in parsing zone: %v", err))
	}

	newFileCache := make(map[string][]byte)
	newRulesetMap := make(map[string]*rule.Ruleset)
	for id, hash := range data.Ruleset {
		fb := GetFile("ruleset", hash)
		if fb == nil {
			ec.ErrCollector.New("policy", "error in getting ruleset file by hash: "+hash)
			continue
		}
		newFileCache["ruleset"+"#"+hash] = fb
		newRulesetMap[id] = rule.ParseRuleset(fb)
	}

	newPolicy := make(map[rule.PolicyId]*rule.Policy)
	for id, hash := range data.Policy {
		pb := GetFile("policy", hash)
		if pb == nil {
			ec.ErrCollector.New("policy", "error in getting policy file by hash: "+hash)
			continue
		}
		newFileCache["policy"+"#"+hash] = pb
		p, err := rule.ParsePolicy(rule.PolicyId(id), hash, pb, newRulesetMap)
		if err != nil {
			ec.ErrCollector.New("policy", fmt.Sprintf("error in parsing policy [id=%s][hash=%s]: %v", id, hash, err))
			continue
		}
		newPolicy[rule.PolicyId(id)] = p
	}

	for id, hash := range data.DeviceGroup {
		ipb := GetFile("segmentgroup", hash)
		if ipb == nil {
			ec.ErrCollector.New("policy", "error in getting segmentgroup file by hash: "+hash)
			continue
		}
		newFileCache["segmentgroup"+"#"+hash] = ipb
		pool := utils.NewIPPool()
		err = pool.Add(strings.Split(strings.TrimSpace(string(ipb)), "\n"))
		if err != nil {
			ec.ErrCollector.New("policy", fmt.Sprintf("error in parsing devicegroup %s: %v", hash, err))
			continue
		}
		pool.Hash = hash
		policy, has := newPolicy[rule.PolicyId(id)]
		if !has {
			newPolicy[rule.PolicyId(id)] = &rule.Policy{UserIP: pool, Id: rule.PolicyId(id)}
		} else {
			policy.UserIP = pool
		}
	}

	for id, hash := range data.BannedUserIps {
		lb := GetFile("banned_user_ips", hash)
		if lb == nil {
			ec.ErrCollector.New("policy", "error in getting banned_user_ips file by hash: "+hash)
			continue
		}
		newFileCache["banned_user_ips"+"#"+hash] = lb
		policy, has := newPolicy[rule.PolicyId(id)]
		if !has {
			ec.ErrCollector.New("policy", fmt.Sprintf("error in parsing BannedUserIps, unmatch id %s:%s ", id, hash))
			continue
		}
		policy.BannedUserIps = utils.NewIPPool()
		err = policy.BannedUserIps.Add(strings.Split(strings.TrimSpace(string(lb)), "\n"))
		if err != nil {
			ec.ErrCollector.New("policy", fmt.Sprintf("error in parsing BannedUserIps %s: %v", hash, err))
			continue
		}
	}

	for id, hash := range data.BannedDnsResolveIps {
		lb := GetFile("banned_dns_resolve_ips", hash)
		if lb == nil {
			ec.ErrCollector.New("policy", "error in getting banned_dns_resolve_ips file by hash: "+hash)
			continue
		}
		newFileCache["banned_dns_resolve_ips"+"#"+hash] = lb
		policy, has := newPolicy[rule.PolicyId(id)]
		if !has {
			ec.ErrCollector.New("policy", fmt.Sprintf("error in parsing BannedDnsResolveIps, unmatch id %s:%s ", id, hash))
			continue
		}
		policy.BannedDnsResolveIps = utils.NewIPPool()
		err = policy.BannedDnsResolveIps.Add(strings.Split(strings.TrimSpace(string(lb)), "\n"))
		if err != nil {
			ec.ErrCollector.New("policy", fmt.Sprintf("error in parsing BannedDnsResolveIps %s: %v", hash, err))
			continue
		}
	}

	rule.Rules = &rule.Rule{RulesetMap: newRulesetMap, PolicyMap: newPolicy, LastUpdateTimestamp: data.LastUpdateTimestamp}
	if p, has := newPolicy[defaultPolicyId]; has {
		rule.Rules.DefaultPolicy = p
	}

	fileCache = newFileCache
	return nil
}

func GetFile(t string, hash string) []byte {
	if p, has := fileCache[t+"#"+hash]; has {
		return p
	}
	for i := 0; i < 3; i++ {
		resp, err := client.Get(apiUrl + "/api/dns/fetch/" + t + "/" + hash)
		if err != nil {
			fmt.Printf("error in getting file %s/%s: %v\n", t, hash, err)
			continue
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			_ = resp.Body.Close()
			fmt.Printf("error in reading file body %s/%s: %v\n", t, hash, err)
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			fmt.Printf("error in getting file with error statuscode %d: %s\n", resp.StatusCode, string(b))
			return nil
		}
		return b
	}
	return nil
}

func BuildReportStatus() (s ReportStatus) {
	s.Id = deviceId
	select {
	case <-syncSignal:
		s.Status = "running"
	default:
		s.Status = "syncing"
	}
	s.LastUpdateTimestamp = rule.Rules.LastUpdateTimestamp
	b, _ := json.Marshal(ec.ErrCollector.Cache)
	s.ErrorMessages = string(b)
	s.Statistics = ExportStatistics()
	return
}

func UpdateConfig(config config) {
	addrMap := make(map[string]*proxy.Proxy)
	for _, p := range forward.DefaultDnsServers {
		addrMap[p.Addr()] = p
	}
	for _, sp := range forward.SpecifiedServers {
		for _, p := range sp.Servers {
			addrMap[p.Addr()] = p
		}
	}
	if len(config.DefaultDnsServers) > 0 {
		var defaultDnsServers []*proxy.Proxy
		for _, addr := range config.DefaultDnsServers {
			addr = AutoAddPort(addr)
			if p, has := addrMap[addr]; has {
				defaultDnsServers = append(defaultDnsServers, p)
			} else {
				p := proxy.NewProxy("forward", addr, "dns")
				p.Start(time.Millisecond * 500)
				defaultDnsServers = append(defaultDnsServers, p)
			}
		}
		forward.DefaultDnsServers = defaultDnsServers
	}
	if config.SpecifiedDnsServers != nil {
		var specifiedDnsServers []forward.SpecifiedDnsServer
		for ipNet, servers := range config.SpecifiedDnsServers {
			r, err := iprange.ParseRange(ipNet)
			if err != nil {
				ec.ErrCollector.New("config", fmt.Sprintf("can not parse SpecifiedDnsServers for net: %s, %v", ipNet, err))
				continue
			}
			var proxies []*proxy.Proxy
			for _, addr := range servers {
				addr = AutoAddPort(addr)
				if p, has := addrMap[addr]; has {
					proxies = append(proxies, p)
				} else {
					p := proxy.NewProxy("forward", addr, "dns")
					p.Start(time.Millisecond * 500)
					proxies = append(proxies, p)
				}
			}
			specifiedDnsServers = append(specifiedDnsServers, forward.SpecifiedDnsServer{
				IPRange: r,
				Servers: proxies,
			})
		}
		forward.SpecifiedServers = specifiedDnsServers
	}
}

func AutoAddPort(s string) string {
	if net.ParseIP(s) != nil {
		return s + ":53"
	}
	return s
}

func UpdateZone(z map[string]string) error {
	var files []*file.ZoneFile
	for origin, fileHash := range z {
		fp, err := GetZoneFile(fileHash)
		if err != nil {
			ec.ErrCollector.New("config", fmt.Sprintf("error in getting zone file for origin %s, hash: %s: %v", origin, fileHash, err))
			continue
		}
		files = append(files, &file.ZoneFile{
			Origin:   dns.Fqdn(origin),
			FilePath: fp,
		})
	}
	return file.ParseZoneFiles(files)
}

const ZoneTempDir = "./"

func GetZoneFile(hash string) (string, error) {
	if _, err := os.Stat(ZoneTempDir + hash + ".zone"); err == nil {
		return ZoneTempDir + hash + ".zone", nil
	}
	for i := 0; i < 3; i++ {
		resp, err := client.Get(apiUrl + "/api/dns/fetch/zone/" + hash)
		if err != nil {
			time.Sleep(time.Millisecond * 100)
			continue
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			_ = resp.Body.Close()
			time.Sleep(time.Millisecond * 100)
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("error in getting zone file %s with error statuscode %d: %s", hash, resp.StatusCode, string(b))
		}
		if err = os.WriteFile(ZoneTempDir+hash+".zone", b, 0644); err != nil {
			return "", fmt.Errorf("error in writing file: %v", err)
		}
		return ZoneTempDir + hash + ".zone", nil
	}
	return "", fmt.Errorf("error in getting zone file with hash %s: too many retry", hash)
}
