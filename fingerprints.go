package tcpraw

import (
	"encoding/binary"
	"time"

	"github.com/google/gopacket/layers"
)

type FingerPrintType int

const (
	TypeLinux FingerPrintType = iota
)

type fingerPrint struct {
	Type    FingerPrintType
	Window  uint16
	Options []layers.TCPOption
	TTL     uint16
}

// options [nop,nop,TS val 1940162183 ecr 1366690553]
var fingerPrintLinux = &fingerPrint{
	Type:   TypeLinux,
	Window: 65535,
	Options: []layers.TCPOption{
		{1, 0, nil},
		{1, 0, nil},
		{8, 10, make([]byte, 10)}, // len = 10
	},
	TTL: 64,
}

var defaultFingerPrint = fingerPrintLinux

var seed uint32

var localtime time.Time // race condition dosn't matter

func init() {
	go localTicker()
	seed = uint32(time.Now().UnixNano())
}

func localTicker() {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop() // Important to prevent resource leak

	for t := range tick.C {
		localtime = t // Using the ticker's time is more precise
		// Or if you prefer actual current time:
		// localtime = time.Now()
	}
}
func makeOption(optType FingerPrintType, options []layers.TCPOption) {
	switch optType {
	case TypeLinux:
		nowMilli := localtime.UnixNano() / 1e9
		binary.BigEndian.PutUint32(options[2].OptionData[:4], uint32(nowMilli))
		binary.BigEndian.PutUint32(options[2].OptionData[4:], uint32(seed+uint32(nowMilli)))
	}
}
