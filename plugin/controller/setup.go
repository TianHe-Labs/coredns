package controller

import (
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"strings"
)

var kafkaAddresses []string
var kafkaTopic = "fiber_dns_log"
var fakeResponse bool = true

var logger *zap.SugaredLogger

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

		for c.NextBlock() {
			if err := parseBlock(c); err != nil {
				return plugin.Error("controller", fmt.Errorf("error in parsing controller block: %v", err))
			}
		}
	}

	logger = initLogger(false)

	go logHandler(kafkaAddresses, kafkaTopic)

	fmt.Printf(`
[API URL] %s
[KAFKA ADDRESSES] %s
[KAFKA TOPIC] %s
`, apiUrl, strings.Join(kafkaAddresses, ","), kafkaTopic)
	go Reporter()
	go monitor()
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &Filter{Next: next}
	})
	return nil
}

func parseBlock(c *caddy.Controller) error {
	switch c.Val() {
	case "kafka_addresses":
		kafkaAddresses = c.RemainingArgs()
		if len(kafkaAddresses) == 1 && kafkaAddresses[0] == "" {
			kafkaAddresses = []string{}
		}
	case "kafka_topic":
		args := c.RemainingArgs()
		if len(args) > 0 && len(args[0]) > 0 {
			kafkaTopic = args[0]
		}
	case "refuse_response":
		fakeResponse = false
	}
	return nil
}

func initLogger(debug bool) *zap.SugaredLogger {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if debug {
		cfg.Level.SetLevel(zapcore.DebugLevel)
	} else {
		cfg.Level.SetLevel(zapcore.InfoLevel)
	}
	logger, _ := cfg.Build()
	defer logger.Sync() // flushes buffer, if any
	return logger.Sugar()
}
