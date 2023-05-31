package tlcp

import (
	"github.com/aacfactory/afssl/gmsm/smx509"
	"runtime"
	"sync"
	"sync/atomic"
)

type cacheEntry struct {
	refs int64
	cert *smx509.Certificate
}

type certCache struct {
	sync.Map
}

var clientCertCache = new(certCache)

type activeCert struct {
	cert *smx509.Certificate
}

func (cc *certCache) active(e *cacheEntry) *activeCert {
	atomic.AddInt64(&e.refs, 1)
	a := &activeCert{e.cert}
	runtime.SetFinalizer(a, func(_ *activeCert) {
		if atomic.AddInt64(&e.refs, -1) == 0 {
			cc.evict(e)
		}
	})
	return a
}

func (cc *certCache) evict(e *cacheEntry) {
	cc.Delete(string(e.cert.Raw))
}

func (cc *certCache) newCert(der []byte) (*activeCert, error) {
	if entry, ok := cc.Load(string(der)); ok {
		return cc.active(entry.(*cacheEntry)), nil
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	entry := &cacheEntry{cert: cert}
	if entry, loaded := cc.LoadOrStore(string(der), entry); loaded {
		return cc.active(entry.(*cacheEntry)), nil
	}
	return cc.active(entry), nil
}
