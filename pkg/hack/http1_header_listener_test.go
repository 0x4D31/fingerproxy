package hack

import (
	"io"
	"net"
	"testing"
)

type fakeListener struct{ conns []net.Conn }

func (l *fakeListener) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, io.EOF
	}
	c := l.conns[0]
	l.conns = l.conns[1:]
	return c, nil
}

func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return nil }

func TestHTTP1HeaderListenerAcceptSkipsEarlyClose(t *testing.T) {
	client1, server1 := net.Pipe()
	client1.Close()
	client2, server2 := net.Pipe()
	go func() {
		io.WriteString(client2, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	}()

	fl := &fakeListener{conns: []net.Conn{server1, server2}}
	hl := NewHTTP1HeaderListener(fl)
	conn, err := hl.Accept()
	if err != nil {
		t.Fatalf("Accept returned error: %v", err)
	}
	hc := conn.(*HTTP1HeaderConn)
	if len(hc.OrderedHeaders()) == 0 {
		t.Fatalf("expected headers to be captured")
	}
	conn.Close()
	client2.Close()
}
