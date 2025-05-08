package tcpraw

import (
	"sync"
	"time"
)

var (
	mu        sync.RWMutex
	localTime time.Time
)

func init() {
	go localTicker()
	seed = uint32(time.Now().UnixNano())
}

func localTicker() {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for t := range tick.C {
		mu.Lock()
		localTime = t
		mu.Unlock()
	}
}

func getLocalTime() time.Time {
	mu.RLock()
	defer mu.RUnlock()
	return localTime
}
