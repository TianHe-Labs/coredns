package controller

import (
	"sync/atomic"
)

var ReceiveCount uint32

type Statistics struct {
	LastIntervalReceiveRequest int `json:"last_interval_receive_request"`
}

func ExportStatistics() Statistics {
	return Statistics{
		LastIntervalReceiveRequest: int(atomic.SwapUint32(&ReceiveCount, 0)),
	}
}
