package rule

import "github.com/coredns/coredns/plugin/controller/utils"

var Rules = &Rule{PolicyMap: make(map[PolicyId]*Policy), RulesetMap: make(map[string]*Ruleset)}

type Rule struct {
	LastUpdateTimestamp int64
	RulesetMap          map[string]*Ruleset
	PolicyMap           map[PolicyId]*Policy
	IPPoolMap           map[string]*utils.IPPool
	DefaultPolicy       *Policy
}

func Judge(policyId PolicyId, domain string) (PolicyOperation, string) {
	p, ok := Rules.PolicyMap[policyId]
	if ok {
		return p.Judge(domain)
	} else {
		return OperationPass, "-1"
	}
}
