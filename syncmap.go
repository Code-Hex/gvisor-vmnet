package vmnet

import (
	"sync"
)

type syncmap[K comparable, V any] struct {
	syncmap *sync.Map
}

func newSyncmap[K comparable, V any]() syncmap[K, V] {
	return syncmap[K, V]{&sync.Map{}}
}

func (s syncmap[K, V]) Load(key K) (v V, ok bool) {
	loaded, ok := s.syncmap.Load(key)
	if !ok {
		return v, false
	}
	return loaded.(V), true
}

func (s syncmap[K, V]) Store(key K, val V) {
	s.syncmap.Store(key, val)
}

func (s syncmap[K, V]) Range(f func(K, V) bool) {
	s.syncmap.Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}

func (s syncmap[K, V]) Delete(key K) {
	s.syncmap.Delete(key)
}
