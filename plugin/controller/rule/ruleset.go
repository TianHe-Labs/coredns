package rule

import (
	"crypto/md5"
	"fmt"
	"strings"
)

type Ruleset struct {
	Hash     string
	Accurate map[string]struct{}
	suffix   TrieNode
}

func (rs *Ruleset) Judge(domain string) bool {
	if _, ok := rs.Accurate[domain]; ok {
		return true
	} else {
		return rs.suffix.HasDomain(domain)
	}
}

func ParseRuleset(b []byte) *Ruleset {
	rs := &Ruleset{Accurate: make(map[string]struct{}), suffix: TrieNode{children: make(map[string]*TrieNode)}, Hash: fmt.Sprintf("%x", md5.Sum(b))}
	for _, rule := range strings.Split(strings.TrimSpace(strings.ReplaceAll(string(b), "\r", "")), "\n") {
		if !strings.HasSuffix(rule, ".") {
			rule = rule + "."
		}
		rule = strings.ToLower(rule)
		if strings.HasPrefix(rule, "*.") {
			rs.suffix.AddDomain(rule[2:])
		} else {
			rs.Accurate[rule] = struct{}{}
		}
	}
	return rs
}
