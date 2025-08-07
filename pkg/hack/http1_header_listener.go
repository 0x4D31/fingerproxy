package hack

import (
	"errors"
	"io"
	"net"
)

// HTTP1HeaderListener wraps an existing listener and returns
// connections that record HTTP/1.x header order.
type HTTP1HeaderListener struct{ net.Listener }

func NewHTTP1HeaderListener(inner net.Listener) *HTTP1HeaderListener {
	return &HTTP1HeaderListener{inner}
}

// Accept waits for and returns the next connection to the listener. It wraps
// accepted connections with HTTP1HeaderConn to capture the order of HTTP/1.x
// headers. If the client closes the connection before sending a complete
// request (resulting in io.EOF or io.ErrUnexpectedEOF) or times out while
// sending headers, the connection is discarded and Accept continues to wait for
// the next one instead of returning an error up the stack which would stop the
// HTTP server.
func (l *HTTP1HeaderListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		hc, err := NewHTTP1HeaderConn(c)
		if err != nil {
			c.Close()
			// Ignore errors where the client disconnects before
			// completing the HTTP request or fails to send headers
			// in time. These should not bring down the HTTP
			// server.
			var ne net.Error
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || (errors.As(err, &ne) && ne.Timeout()) {
				continue
			}
			return nil, err
		}
		return hc, nil
	}
}
