package hack

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// HTTP1HeaderConn wraps a net.Conn and records the order of HTTP/1.x
// request headers. Only the first request on the connection is captured.
// Read returns the captured request bytes followed by the remaining bytes
// from the underlying connection so http.ReadRequest behaves normally.
// Deadlines set on the underlying connection after the wrapper is created
// still apply, although reads may succeed on buffered data even if the
// deadline has expired.
const maxHeaderBytes = 64 * 1024 // 64 KiB

type HTTP1HeaderConn struct {
	net.Conn
	r       io.Reader
	headers []string
}

// NewHTTP1HeaderConn reads from conn until the end of the HTTP/1.x header
// block (\r\n\r\n) and returns a connection that replays those bytes and
// exposes the ordered header names.
func NewHTTP1HeaderConn(conn net.Conn) (*HTTP1HeaderConn, error) {
	// give slow clients only a short window to finish sending headers
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	br := bufio.NewReader(conn)
	var buf bytes.Buffer
	buf.Grow(4096)
	var names []string

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		buf.WriteString(line)
		if buf.Len() > maxHeaderBytes {
			return nil, fmt.Errorf("header block exceeds %d bytes", maxHeaderBytes)
		}
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
		if i := strings.IndexByte(line, ':'); i > 0 {
			name := strings.ToLower(strings.TrimSpace(line[:i]))
			names = append(names, name)
		}
	}

	return &HTTP1HeaderConn{
		Conn:    conn,
		r:       io.MultiReader(bytes.NewReader(buf.Bytes()), br),
		headers: names,
	}, nil
}

func (c *HTTP1HeaderConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *HTTP1HeaderConn) OrderedHeaders() []string {
	out := make([]string, len(c.headers))
	copy(out, c.headers)
	return out
}
