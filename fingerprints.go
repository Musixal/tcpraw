package tcpraw

import (
	"encoding/binary"

	"github.com/google/gopacket/layers"
)

var seed uint32

// Fingerprint used to mimic a Linux TCP stack (NOP, NOP, Timestamp)
var linuxFingerPrint = &fingerPrint{
	Window: 65535,
	TTL:    64,
	Options: []layers.TCPOption{
		{OptionType: 1, OptionLength: 0, OptionData: nil},               // NOP
		{OptionType: 1, OptionLength: 0, OptionData: nil},               // NOP
		{OptionType: 8, OptionLength: 10, OptionData: make([]byte, 10)}, // Timestamp
	},
}

type fingerPrint struct {
	Window  uint16
	TTL     uint16
	Options []layers.TCPOption
}

// Sets TSval and TSecr in the timestamp option
func setTimestampOption(options []layers.TCPOption) {
	// Use current time as a timestamp
	now := uint32(getLocalTime().UnixMilli())

	// Timestamp option is at index 2
	data := options[2].OptionData

	// Set TSval (Timestamp Value)
	binary.BigEndian.PutUint32(data, now)

	// Set TSecr (Timestamp Echo Reply) based on seed + current time
	binary.BigEndian.PutUint32(data[4:], seed+now)
}
