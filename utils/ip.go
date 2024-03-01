package utils

import (
	"encoding/hex"
	"net"
	"strconv"
)

func IpAddr2Hex(addr string) string {
	ip := net.ParseIP(addr)
	hexIP := hex.EncodeToString(ip.To4())
	return hexIP
}

func Decimal2Hex(num int) string {
	hexadecimal := strconv.FormatInt(int64(num), 16)
	return hexadecimal
}
