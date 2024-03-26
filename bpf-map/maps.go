package bpf_map

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type Mapper interface {
	Get(key MapKey) (MapValue, error)
	Set(key MapKey, val MapValue) error
	Del(key MapKey) error
	List() (mapCache map[MapKey]MapValue, capacity int)
}

func NewMapper() (Mapper, error) {
	newMap, err := CreateOnceMapWithPin(PinPath, MapName, MapType, MapKeySize, MapValueSize, MaxEntries, MapFlags)
	if nil != err {
		return nil, err
	}

	em := &ebpfMap{
		m: newMap,
	}
	return em, nil
}

type ebpfMap struct {
	m *ebpf.Map
}

func (em *ebpfMap) Get(key MapKey) (MapValue, error) {
	var mapVal MapValue
	err := em.m.Lookup(key, &mapVal)
	if nil != err {
		return MapValue{}, fmt.Errorf("failed to read ebpf map '%+v', error: %w", key, err)
	}

	return mapVal, nil
}

func (em *ebpfMap) Set(key MapKey, val MapValue) error {
	err := em.m.Put(key, val)
	if nil != err {
		return fmt.Errorf("failed to set key '%+v', value '%+v' into ebpf map, error: %w", key, val, err)
	}

	return nil
}

func (em *ebpfMap) Del(key MapKey) error {
	err := em.m.Delete(key)
	if nil != err {
		return fmt.Errorf("failed to delete ebpf map data '%+v', error: %w", key, err)
	}

	return nil
}

func (em *ebpfMap) List() (map[MapKey]MapValue, int) {
	mapCache := make(map[MapKey]MapValue)

	iterator := em.m.Iterate()
	key, value := MapKey{}, MapValue{}
	for iterator.Next(&key, &value) {
		tmpKey := key
		tmpValue := value
		mapCache[tmpKey] = tmpValue
	}

	return mapCache, len(mapCache)
}
