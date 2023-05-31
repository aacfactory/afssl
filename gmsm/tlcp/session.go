package tlcp

import (
	"container/list"
	"github.com/aacfactory/afssl/gmsm/smx509"
	"sync"
	"time"
)

type SessionState struct {
	sessionId        []byte
	vers             uint16
	cipherSuite      uint16
	masterSecret     []byte
	peerCertificates []*smx509.Certificate
	createdAt        time.Time
}

type SessionCache interface {
	Get(sessionKey string) (session *SessionState, ok bool)
	Put(sessionKey string, cs *SessionState)
}

type lruSessionCache struct {
	sync.Mutex

	m        map[string]*list.Element
	q        *list.List
	capacity int
}

type lruSessionCacheEntry struct {
	sessionKey string
	state      *SessionState
}

func NewLRUSessionCache(capacity int) SessionCache {
	const defaultSessionCacheCapacity = 64

	if capacity < 1 {
		capacity = defaultSessionCacheCapacity
	}
	return &lruSessionCache{
		m:        make(map[string]*list.Element),
		q:        list.New(),
		capacity: capacity,
	}
}

func (c *lruSessionCache) Put(sessionKey string, cs *SessionState) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		if cs == nil {
			c.q.Remove(elem)
			delete(c.m, sessionKey)
		} else {
			entry := elem.Value.(*lruSessionCacheEntry)
			entry.state = cs
			c.q.MoveToFront(elem)
		}
		return
	}

	if c.q.Len() < c.capacity {
		entry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(entry)
		return
	}

	elem := c.q.Back()
	entry := elem.Value.(*lruSessionCacheEntry)
	delete(c.m, entry.sessionKey)
	entry.sessionKey = sessionKey
	entry.state = cs
	c.q.MoveToFront(elem)
	c.m[sessionKey] = elem
}

func (c *lruSessionCache) Get(sessionKey string) (*SessionState, bool) {
	c.Lock()
	defer c.Unlock()

	if sessionKey == "" {
		elem := c.q.Front()
		if elem == nil {
			return nil, false
		}
		return elem.Value.(*lruSessionCacheEntry).state, true
	}

	if elem, ok := c.m[sessionKey]; ok {
		c.q.MoveToFront(elem)
		return elem.Value.(*lruSessionCacheEntry).state, true
	}
	return nil, false
}
