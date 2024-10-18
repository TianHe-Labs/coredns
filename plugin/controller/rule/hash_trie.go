package rule

import (
	"hash/fnv"
	"strings"
)

type HashTrieNode struct {
	leaf     bool
	children map[uint32]*HashTrieNode
}

func NewHashTrieTree() *HashTrieNode {
	return &HashTrieNode{children: make(map[uint32]*HashTrieNode)}
}

func (t *HashTrieNode) AddDomain(domain string) {
	var ok bool
	p := t
	parts := strings.Split(domain, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		c := hash(parts[i])
		if _, ok = p.children[c]; !ok {
			p.children[c] = &HashTrieNode{children: make(map[uint32]*HashTrieNode)}
		}
		p = p.children[c]
		if p.leaf {
			break
		}
	}
	p.leaf = true
	return
}

func (t *HashTrieNode) HasDomain(domain string) bool {
	var ok bool
	p := t
	parts := strings.Split(domain, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		c := hash(parts[i])
		if _, ok = p.children[c]; !ok {
			return false
		}
		p = p.children[c]
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

func hash(d string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(d))
	return h.Sum32()
}
