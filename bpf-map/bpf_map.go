package bpf_map

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// MapKey represents NAT original IP addr
type MapKey struct {
	IP uint32
}

// MapValue represents NAT new IP addr
type MapValue struct {
	IP uint32
}

func NewMapKey(data uint32) MapKey {
	return MapKey{IP: data}
}

func NewMapValue(data uint32) MapValue {
	return MapValue{IP: data}
}

func CreateOnceMapWithPin(pinPath string, name string, mapType ebpf.MapType,
	keySize, valueSize, maxEntries, flags uint32) (*ebpf.Map, error) {
	isPathExist, err := IsPathExist(pinPath)
	if nil != err {
		return nil, fmt.Errorf("failed to check whether path '%s' exists, error: %w", pinPath, err)
	}
	if isPathExist {
		return GetMapByPinned(pinPath)
	}

	newMap, err := CreateMap(name, mapType, keySize, valueSize, maxEntries, flags)
	if nil != err {
		return nil, fmt.Errorf("failed to create ebpf map, error: %w", err)
	}
	err = newMap.Pin(pinPath)
	if nil != err {
		return nil, fmt.Errorf("failed to pin map to %s, error: %w", pinPath, err)
	}

	return newMap, nil
}

func CreateMap(name string, mapType ebpf.MapType,
	keySize, valueSize, maxEntries, flags uint32) (*ebpf.Map, error) {
	mapSepc := &ebpf.MapSpec{
		Name:       name,
		Type:       mapType,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
		Flags:      flags,
	}
	newMap, err := ebpf.NewMap(mapSepc)
	if nil != err {
		return nil, err
	}
	return newMap, nil
}

func GetMapByPinned(pinPath string) (*ebpf.Map, error) {
	pinnedMap, err := ebpf.LoadPinnedMap(pinPath, &ebpf.LoadPinOptions{})
	if nil != err {
		return nil, err
	}

	return pinnedMap, nil
}
