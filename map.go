package sniffer

import (
	"net/http"
	"sync"
)

type Map struct {
	sync.RWMutex
	reqRes map[string]*http.Request
}

var reqRes = NewMap()

func NewMap() *Map {
	return &Map{
		reqRes: map[string]*http.Request{},
	}
}

func (m *Map) Add(key string, req *http.Request) {
	m.Lock()
	defer m.Unlock()
	m.reqRes[key] = req
}

func (m *Map) Get(key string) (*http.Request, bool) {
	m.RLock()
	defer m.RUnlock()
	req, ok := m.reqRes[key]
	return req, ok
}

func (m *Map) Delete(key string) {
	m.Lock()
	delete(m.reqRes, key)
	m.Unlock()
}
