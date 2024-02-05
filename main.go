package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
)

func main() {
	addr := "10.6.183.22"
	addrHex := ipAddr2Hex(addr)
	fmt.Println(addrHex)

	// decimal to hex
	hexadecimal := decimal2Hex(6666)
	fmt.Println(hexadecimal)
}

func ipAddr2Hex(addr string) string {
	ip := net.ParseIP(addr)
	hexIP := hex.EncodeToString(ip.To4())
	return hexIP
}

func decimal2Hex(num int) string {
	hexadecimal := strconv.FormatInt(int64(num), 16)
	return hexadecimal
}
