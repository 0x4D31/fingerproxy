// Package `metadata` has a struct that stores information captured by
// `proxyserver`. Package `fingerprint` uses these information to create
// fingerprints.
package metadata

import "crypto/tls"

// Metadata is the data we captured from the connection for fingerprinting.
// Currently only TLS ClientHello and certain HTTP2 frames included, more can
// be added in the future.
type Metadata struct {
	// ClientHelloRecord is the raw TLS ClientHello bytes that
	// include TLS record header and handshake header
	ClientHelloRecord []byte

	// ConnectionState represents the TLS connection state
	ConnectionState tls.ConnectionState

	// HTTP2Frames includes certain HTTP2 frames data
	HTTP2Frames HTTP2FingerprintingFrames

	// IsQUIC indicates the handshake came over QUIC/UDP.
	IsQUIC bool

	// OrderedHTTP1Headers lists request header names in the order they
	// were received for HTTP/1.x connections. Names are lower-case and
	// may appear multiple times if the client sent duplicates.
	OrderedHTTP1Headers []string
}

// OrderedHeaders returns the HTTP header names in the order they were received.
// If HTTP/1.x ordered headers are available they are returned directly;
// otherwise the order is determined from captured HTTP/2 frames.
func (m *Metadata) OrderedHeaders() []string {
	if len(m.OrderedHTTP1Headers) > 0 {
		return m.OrderedHTTP1Headers
	}
	return m.HTTP2Frames.OrderedHeaders()
}
