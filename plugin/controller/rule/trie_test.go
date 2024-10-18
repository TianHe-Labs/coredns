package rule

import (
	"bitbucket.org/struggle888/go-utils/file"
	"math/rand"
	"strings"
	"testing"
	"time"
)

var domains = loadDomains()

func loadDomains() (domains []string) {
	_ = file.FileLineHandler("../illegal_input_domains.txt", func(s string) {
		domains = append(domains, strings.TrimSpace(s))
	})
	return
}

func buildTrieTree(count int) *TrieNode {
	n := NewTrieTree()
	for i := 0; i < count; i++ {
		p := strings.Split(domains[i], ".")
		n.AddDomain(strings.Join(p[len(p)-2:], "."))
	}
	return n
}

func buildHashTrieTree(count int) *HashTrieNode {
	n := NewHashTrieTree()
	for i := 0; i < count; i++ {
		p := strings.Split(domains[i], ".")
		n.AddDomain(strings.Join(p[len(p)-2:], "."))
	}
	return n
}

func BenchmarkTrieNode_HasDomain_10000(b *testing.B) {
	tree := buildTrieTree(10000)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(domains), func(i, j int) { domains[i], domains[j] = domains[j], domains[i] })
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.HasDomain(domains[i%len(domains)])
	}
}

func BenchmarkHashTrieNode_HasDomain_10000(b *testing.B) {
	tree := buildHashTrieTree(10000)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(domains), func(i, j int) { domains[i], domains[j] = domains[j], domains[i] })
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.HasDomain(domains[i%len(domains)])
	}
}

func BenchmarkTrieNode_HasDomain_50000(b *testing.B) {
	tree := buildTrieTree(50000)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(domains), func(i, j int) { domains[i], domains[j] = domains[j], domains[i] })
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.HasDomain(domains[i%len(domains)])
	}
}

func BenchmarkHashTrieNode_HasDomain_50000(b *testing.B) {
	tree := buildHashTrieTree(50000)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(domains), func(i, j int) { domains[i], domains[j] = domains[j], domains[i] })
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.HasDomain(domains[i%len(domains)])
	}
}

func BenchmarkTrieNode_HasDomain_200000(b *testing.B) {
	tree := buildTrieTree(200000)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(domains), func(i, j int) { domains[i], domains[j] = domains[j], domains[i] })
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.HasDomain(domains[i%len(domains)])
	}
}

func BenchmarkHashTrieNode_HasDomain_200000(b *testing.B) {
	tree := buildHashTrieTree(200000)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(domains), func(i, j int) { domains[i], domains[j] = domains[j], domains[i] })
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.HasDomain(domains[i%len(domains)])
	}
}

func BenchmarkHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hash(domains[i%len(domains)])
	}
}
