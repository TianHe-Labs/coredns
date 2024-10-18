package controller

import (
	"time"
)

var ReceiveCount uint32
var LastTenSecondReceiveCount uint32

func monitor() {
	for {
		time.Sleep(time.Second * 10)
		LastTenSecondReceiveCount = ReceiveCount
		ReceiveCount = 0
		logger.Infof("Last 10 seconds receive: %d,  log cache: %d", LastTenSecondReceiveCount, len(logCh))
	}
}

type Statistics struct {
	LastIntervalReceiveRequest int `json:"last_interval_receive_request"`
}

func ExportStatistics() Statistics {
	return Statistics{
		LastIntervalReceiveRequest: int(LastTenSecondReceiveCount),
	}
}
