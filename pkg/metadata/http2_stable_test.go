package metadata_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	fp "github.com/0x4D31/fingerproxy/pkg/fingerprint"
	"github.com/0x4D31/fingerproxy/pkg/metadata"
	"github.com/0x4D31/fingerproxy/pkg/proxyserver"
	"golang.org/x/net/http2"
)

func generateCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func startTestServer(t *testing.T, handler http.Handler) (addr string, stop func()) {
	t.Helper()
	cert := generateCert(t)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	srv := proxyserver.NewServer(ctx, handler, tlsConf)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	return "https://" + ln.Addr().String(), func() {
		cancel()
		ln.Close()
	}
}

func newH2Client(t *testing.T) *http.Client {
	t.Helper()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		t.Fatal(err)
	}
	tr.DisableKeepAlives = false
	return &http.Client{Transport: tr}
}

func TestStableFingerprintOnReload(t *testing.T) {
	fpChan := make(chan string, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md, ok := metadata.FromContext(r.Context())
		if !ok {
			t.Fatal("metadata missing")
		}
		p := &fp.HTTP2FingerprintParam{MaxPriorityFrames: math.MaxUint}
		fpStr, err := p.HTTP2Fingerprint(md)
		if err != nil {
			t.Fatal(err)
		}
		fpChan <- fpStr
		io.WriteString(w, "ok")
	})

	url, stop := startTestServer(t, handler)
	defer stop()

	client := newH2Client(t)

	for i := 0; i < 2; i++ {
		resp, err := client.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	fp1 := <-fpChan
	fp2 := <-fpChan
	if fp1 != fp2 {
		t.Fatalf("fingerprints differ: %s vs %s", fp1, fp2)
	}
}
