package utils

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"
)

func PanicError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func PrintHexLikeShark(data []byte) {
	count := 0
	for _, b := range data {
		if count%16 == 0 {
			fmt.Println(" ")
		}
		if count%8 == 0 {
			fmt.Print(" ")
		}
		fmt.Printf("%02x ", b)
		count++
	}
}

func ReadSsidList(fileName string) ([]string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)

	result := make([]string, 0)

	for fileScanner.Scan() {
		result = append(result, fileScanner.Text())
	}
	return result, nil
}

var seed = time.Now().Unix()

func GenerateRandMac() [6]byte {
	var result [6]byte
	src := rand.NewSource(seed)
	r := rand.New(src)

	for i := 0; i < 6; i++ {
		result[i] = uint8(r.Intn(0xff))
	}
	seed -= r.Int63n(0xff)

	return result
}

func BytesToMac(r [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", r[0], r[1], r[2], r[3], r[4], r[5])
}

func ExecutingBar() {
	bar := "|/-\\"
	seq := 0
	for {
		fmt.Printf("Executing... %s\r", string(bar[seq]))
		seq++
		seq %= len(bar)
		time.Sleep(time.Second / 10)
	}
}
