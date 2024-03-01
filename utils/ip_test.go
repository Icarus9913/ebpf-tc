package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIpAddr2Hex(t *testing.T) {
	addr := "10.6.183.22"
	addrHex := IpAddr2Hex(addr)
	assert.Equal(t, "0a06b716", addrHex)
}

func TestDecimal2Hex(t *testing.T) {
	decimal := 6666
	hex := Decimal2Hex(decimal)
	assert.Equal(t, "1a0a", hex)
}
