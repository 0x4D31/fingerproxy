package hack

import "net"

// HTTP1HeaderListener wraps an existing listener and returns
// connections that record HTTP/1.x header order.
type HTTP1HeaderListener struct{ net.Listener }

func NewHTTP1HeaderListener(inner net.Listener) *HTTP1HeaderListener {
	return &HTTP1HeaderListener{inner}
}

func (l *HTTP1HeaderListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	hc, err := NewHTTP1HeaderConn(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	return hc, nil
}
