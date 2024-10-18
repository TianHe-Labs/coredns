package rule

import (
	"strings"
)

type TrieNode struct {
	leaf     bool
	children map[string]*TrieNode
}

func NewTrieTree() *TrieNode {
	return &TrieNode{children: make(map[string]*TrieNode)}
}

func (t *TrieNode) AddDomain(domain string) {
	var ok bool
	p := t
	parts := strings.Split(domain, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		if _, ok = p.children[parts[i]]; !ok {
			p.children[parts[i]] = &TrieNode{children: make(map[string]*TrieNode)}
		}
		p = p.children[parts[i]]
		if p.leaf {
			break
		}
	}
	p.leaf = true
	return
}

func (t *TrieNode) HasDomain(domain string) bool {
	var ok bool
	p := t
	parts := strings.Split(domain, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		if _, ok = p.children[parts[i]]; !ok {
			return false
		}
		p = p.children[parts[i]]
		if p.leaf {
			if i == 0 {
				return false
			} else {
				return true
			}
		}
	}
	return false
}
