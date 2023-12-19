package afssl_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/aacfactory/afssl"
	"net"
	"testing"
	"time"
)

func TestSSC(t *testing.T) {
	caPEM, keyPEM, caErr := afssl.CreateCA("CN", 10)
	if caErr != nil {
		t.Error("ca:", caErr)
		return
	}
	serverTLS, clientTLS, configErr := afssl.SSC(caPEM, keyPEM)
	if configErr != nil {
		t.Error("ca:", configErr)
		return
	}
	ctx, cancel := context.WithCancel(context.TODO())
	sscListen(t, ctx, serverTLS)
	time.Sleep(1 * time.Second)
	sscClient(t, ctx, clientTLS)
	cancel()
}

func sscListen(t *testing.T, ctx context.Context, config *tls.Config) {
	ln, lnErr := tls.Listen("tcp", "127.0.0.1:8888", config)
	if lnErr != nil {
		t.Error("listen:", lnErr)
		return
	}
	go func(ctx context.Context, ln net.Listener) {
		for {
			select {
			case <-ctx.Done():
				_ = ln.Close()
				return
			default:
				conn, connErr := ln.Accept()
				if connErr != nil {
					t.Error("listen:", connErr)
					return
				}
				p := make([]byte, 1024)
				n, readErr := conn.Read(p)
				if readErr != nil {
					t.Error("listen:", readErr)
					return
				}
				fmt.Println(string(p[:n]))
			}
		}
	}(ctx, ln)
}

func sscClient(t *testing.T, ctx context.Context, config *tls.Config) {
	conn, connErr := tls.Dial("tcp", "127.0.0.1:8888", config)
	if connErr != nil {
		t.Error("client:", connErr)
		return
	}
	_, writeErr := conn.Write([]byte(time.Now().String()))
	if writeErr != nil {
		t.Error("client:", writeErr)
		return
	}
	_ = conn.Close()
}
