package rule

import (
	"fmt"
	ec "github.com/coredns/coredns/plugin/controller/error"
	"github.com/coredns/coredns/plugin/controller/utils"
	"strconv"
	"strings"
)

type PolicyId string

type PolicyOperation int

const OperationPass PolicyOperation = 1
const OperationForbidden PolicyOperation = 0

type Policy struct {
	Id                  PolicyId
	Hash                string
	Rules               []*PolicyRule
	UserIP              *utils.IPPool
	BannedUserIps       *utils.IPPool `json:"banned_user_ips"`
	BannedDnsResolveIps *utils.IPPool `json:"banned_dns_resolve_ips"`
}

type PolicyRule struct {
	Id        string
	Operation PolicyOperation
}

func (p *Policy) Judge(domain string) (PolicyOperation, string) {
	for i := len(p.Rules) - 1; i >= 0; i-- {
		if Rules.RulesetMap[p.Rules[i].Id].Judge(domain) {
			return p.Rules[i].Operation, p.Rules[i].Id
		}
	}
	return OperationPass, "-1"
}

func ParsePolicy(Id PolicyId, hash string, b []byte, rules map[string]*Ruleset) (*Policy, error) {
	policy := &Policy{Hash: hash, Id: Id}
	for _, p := range strings.Split(strings.TrimSpace(strings.ReplaceAll(string(b), "\r", "")), "\n") {
		parts := strings.Split(p, "|")
		if len(parts) != 2 {
			ec.ErrCollector.New("policy", fmt.Sprintf("error in parsing policy line [id=%s]: %s", Id, p))
			continue
		}
		_, ok := rules[parts[0]]
		if !ok {
			ec.ErrCollector.New("policy", fmt.Sprintf("error in parsing ruleset, unknown ruleset [id=%s]: %s", Id, parts[0]))
			continue
		}
		op, err := strconv.Atoi(parts[1])
		if err != nil {
			ec.ErrCollector.New("policy", fmt.Sprintf("error in parsing ruleset operation to int [id=%s]: %s", Id, parts[1]))
			continue
		}
		if PolicyOperation(op) != OperationPass && PolicyOperation(op) != OperationForbidden {
			ec.ErrCollector.New("policy", fmt.Sprintf("unknown policy operation [id=%s]: %d", Id, op))
			continue
		}
		policy.Rules = append(policy.Rules, &PolicyRule{Operation: PolicyOperation(op), Id: parts[0]})
	}
	return policy, nil
}
