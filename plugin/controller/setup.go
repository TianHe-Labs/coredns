package controller

import (
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

var kafkaAddresses []string
var kafkaTopic string = "fiber_dns_log"

func init() {
	plugin.Register("controller", setup)
}

func setup(c *caddy.Controller) error {
	for c.Next() {
		params := c.RemainingArgs()
		if len(params) == 0 {
			return plugin.Error("controller", fmt.Errorf("at least one argument is required"))
		}
		apiUrl = params[0]
		if len(params) > 1 {
			deviceId = params[1]
		} else {
			deviceId = "test"
		}
	}

	for c.NextBlock() {
		if err := parseBlock(c); err != nil {
			return plugin.Error("controller", fmt.Errorf("error in parsing controller block: %v", err))
		}
	}

	if len(kafkaAddresses) > 0 {
		go logHandler(kafkaAddresses, kafkaTopic)
	}
	go Reporter()
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &Filter{Next: next}
	})
	return nil
}

func parseBlock(c *caddy.Controller) error {
	switch c.Val() {
	case "kafka_addresses":
		kafkaAddresses = c.RemainingArgs()
	case "kafka_topic":
		args := c.RemainingArgs()
		if len(args) > 0 {
			kafkaTopic = args[0]
		}
	}
	return nil
}
