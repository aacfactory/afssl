package tlcp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

type ProtocolDetectConn struct {
	net.Conn
	major, minor uint8
	recordHeader []byte
}

func (c *ProtocolDetectConn) protocolVersion() (major uint8, minor uint8) {
	return c.major, c.minor
}

func (c *ProtocolDetectConn) Raw() net.Conn {
	return c.Conn
}

func (c *ProtocolDetectConn) ReadFirstHeader() error {
	c.recordHeader = make([]byte, 5)
	_, err := io.ReadFull(c.Conn, c.recordHeader)
	c.major, c.minor = c.recordHeader[1], c.recordHeader[2]
	return err
}

func (c *ProtocolDetectConn) Read(b []byte) (n int, err error) {
	if len(c.recordHeader) == 0 {
		return c.Conn.Read(b)
	}

	if len(b) >= len(c.recordHeader) {
		n = copy(b, c.recordHeader)
		c.recordHeader = nil
		if len(b) > n {
			var n1 = 0
			n1, err = c.Conn.Read(b[n:])
			n += n1
			if err != nil {
				return n, err
			}
		}
		return n, nil
	} else {
		p := c.recordHeader[:len(b)]
		n = len(b)
		copy(b, p)
		c.recordHeader = c.recordHeader[len(b):]
		if len(c.recordHeader) == 0 {
			c.recordHeader = nil
		}
		return n, nil
	}
}

type ProtocolNotSupportError struct{}

func (ProtocolNotSupportError) Error() string   { return "tlcp: unknown protocol version" }
func (ProtocolNotSupportError) Timeout() bool   { return false }
func (ProtocolNotSupportError) Temporary() bool { return false }

var notSupportError = &ProtocolNotSupportError{}

type protocolSwitcherListener struct {
	net.Listener
	tlcpConfig *Config
	tlsConfig  *tls.Config
}

func (l *protocolSwitcherListener) Accept() (net.Conn, error) {
	rawConn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newProtocolSwitchServerConn(l, rawConn), nil
}

func NewProtocolSwitcherListener(inner net.Listener, config *Config, tlsConfig *tls.Config) net.Listener {
	if inner == nil || (config == nil && tlsConfig == nil) {
		return nil
	}
	l := new(protocolSwitcherListener)
	l.Listener = inner
	l.tlcpConfig = config
	l.tlsConfig = tlsConfig
	return l
}

func ListenWithAutoProtocolSwitcher(network, addr string, config *Config, tlsConfig *tls.Config) (net.Listener, error) {
	if config == nil && tlsConfig == nil {
		return nil, errors.New("tlcp: neither tlcp config, tls config is nil")
	}
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("tlcp: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return NewProtocolSwitcherListener(l, config, tlsConfig), nil
}

type ProtocolSwitchServerConn struct {
	net.Conn
	lock    *sync.Mutex
	p       *ProtocolDetectConn
	ln      *protocolSwitcherListener
	wrapped net.Conn
}

func newProtocolSwitchServerConn(ln *protocolSwitcherListener, rawConn net.Conn) *ProtocolSwitchServerConn {
	p := &ProtocolDetectConn{Conn: rawConn}
	return &ProtocolSwitchServerConn{
		Conn:    rawConn,
		ln:      ln,
		p:       p,
		lock:    new(sync.Mutex),
		wrapped: nil,
	}
}

func (c *ProtocolSwitchServerConn) detect() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.wrapped != nil {
		return nil
	}

	err := c.p.ReadFirstHeader()
	if err != nil {
		return err
	}
	switch c.p.major {
	case 0x01:
		if c.ln.tlcpConfig == nil {
			return fmt.Errorf("tlcp: tlcp config not set")
		}
		c.wrapped = Server(c.p, c.ln.tlcpConfig)
	case 0x03:
		if c.ln.tlsConfig == nil {
			return fmt.Errorf("tlcp: tls config not set")
		}
		c.wrapped = tls.Server(c.p, c.ln.tlsConfig)
	default:
		return notSupportError
	}
	return nil
}

func (c *ProtocolSwitchServerConn) ProtectedConn() net.Conn {
	return c.wrapped
}

func (c *ProtocolSwitchServerConn) Read(b []byte) (n int, err error) {
	if c.wrapped == nil {
		err = c.detect()
		if err != nil {
			return 0, err
		}
	}
	return c.wrapped.Read(b)
}

func (c *ProtocolSwitchServerConn) Write(b []byte) (n int, err error) {
	if c.wrapped == nil {
		err = c.detect()
		if err != nil {
			return 0, err
		}
	}
	return c.wrapped.Write(b)
}
