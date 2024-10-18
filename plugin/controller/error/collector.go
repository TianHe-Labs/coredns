package ec

import (
	"go.uber.org/zap"
	"time"
)

var ErrCollector = &Collector{Cache: ErrorCache{PolicyError: []Error{}}}

type Collector struct {
	Cache  ErrorCache
	Logger *zap.SugaredLogger
}

type ErrorCache struct {
	PolicyError []Error `json:"policy_error"`
	ConfigError []Error `json:"config_error"`
}

type Error struct {
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

func (ec *Collector) New(t string, msg string) {
	ec.Logger.Errorf("EC Error [ %s ]: %s", t, msg)
	switch t {
	case "policy":
		ec.Cache.PolicyError = append(ec.Cache.PolicyError, Error{Message: msg, Timestamp: time.Now().UnixNano()})
	case "config":
		ec.Cache.ConfigError = append(ec.Cache.ConfigError, Error{Message: msg, Timestamp: time.Now().UnixNano()})
	}
}
