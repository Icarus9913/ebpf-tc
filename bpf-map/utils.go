package bpf_map

import (
	"encoding/binary"
	"net"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
)

const (
	PinPath      = "/sys/fs/bpf/tc/globals/nat_ip"
	MapName      = "nat_map"
	MapType      = ebpf.Hash
	MapKeySize   = uint32(unsafe.Sizeof(MapKey{}))
	MapValueSize = uint32(unsafe.Sizeof(MapValue{}))
	MaxEntries   = 255
	MapFlags     = 0
)

func IsPathExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if nil != err {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func Ipv4ToUint32(addr string) uint32 {
	netIP := net.ParseIP(addr)
	// TODO
	if netIP == nil {
		return 0
	}

	return binary.BigEndian.Uint32(netIP.To4())
}

func Uint32ToIpv4(data uint32) string {
	ipByte := make([]byte, 4)
	binary.BigEndian.PutUint32(ipByte, data)
	return net.IP(ipByte).String()
}
