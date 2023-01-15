package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/beacon-flooding/utils"
	"github.com/google/gopacket/pcap"
)

type SimpleRadioTap struct {
	HeaderRevision   uint8
	HeaderPad        uint8
	HeaderLength     uint16
	Present1         uint32
	Present2         uint32
	Flags            uint8
	DataRate         uint8
	ChannelFrequency uint16
	ChannelFlags     uint16
	AnthenaSignal    uint8
	RxFlags          uint16
	AnthenaSignalDup uint8
	Anthena          uint8
}

type SimpleDot11 struct {
	Type               uint16
	Duration           uint16
	DestinationAddress [6]byte
	SourceAddress      [6]byte
	BssId              [6]byte
	FragSeqNum         uint16
}

type SimpleDot11Beacon struct {
	Timestamp uint64
	Interval  uint16
	Flags     uint16
}

type SimpleDot11Info struct {
	Number  uint8
	Length  uint8
	Content string
}

func (info SimpleDot11Info) WriteToBuffer(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, info.Number)
	binary.Write(buf, binary.LittleEndian, info.Length)
	buf.WriteString(info.Content)
}

func main() {
	ifSelect := os.Args[1]
	handler, err := pcap.OpenLive(ifSelect, 1600, true, pcap.BlockForever)
	utils.PanicError(err)

	// buf := gopacket.NewSerializeBuffer()
	// opts := gopacket.SerializeOptions{}

	radioTap := SimpleRadioTap{
		HeaderRevision:   0x00,
		HeaderPad:        0x00,
		HeaderLength:     0x0018,
		Present1:         0xa0000000,
		Present2:         0x00000000,
		Flags:            0x00,
		DataRate:         0x02,
		ChannelFrequency: 0x096c,
		ChannelFlags:     0x00a0,
		AnthenaSignal:    0xab,
		RxFlags:          0x0000,
		AnthenaSignalDup: 0xab,
		Anthena:          0,
	}

	dot11 := SimpleDot11{
		Type:               0x0080,
		Duration:           0x0000,
		DestinationAddress: [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		SourceAddress:      [6]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
		BssId:              [6]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
		FragSeqNum:         0x1dc0,
	}

	beacon := SimpleDot11Beacon{
		Timestamp: uint64(time.Now().Unix()),
		Interval:  0x0064,
		Flags:     0x1c31,
	}

	ssidValue := "hellotcp544D"
	ssid := SimpleDot11Info{
		Number:  0,
		Length:  uint8(len(ssidValue)),
		Content: ssidValue,
	}

	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, radioTap)
	binary.Write(buf, binary.LittleEndian, dot11)
	binary.Write(buf, binary.LittleEndian, beacon)

	binary.Write(buf, binary.LittleEndian, ssid.Number)
	binary.Write(buf, binary.LittleEndian, ssid.Length)
	buf.WriteString(ssid.Content)

	fmt.Printf("% 2x", buf.Bytes())

	// gopacket.SerializeLayers(buf, opts, a, b, c)
	packetReady := buf.Bytes()

	err = handler.WritePacketData(packetReady)
	utils.PanicError(err)
}
