package fingerprint

import (
	"net/http"
	"testing"

	"github.com/0x4D31/fingerproxy/pkg/metadata"
)

func TestJA4HHeaderInjector(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.Host = "example.com"
	req.Header.Set("Host", "example.com")
	req.Header.Set("User-Agent", "curl/8.7.1")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "fr")
	req.Header.Set("Cookie", "SID=123; theme=dark")
	req.Header.Set("Referer", "https://example.com/start")

	ordered := []string{
		"host",
		"user-agent",
		"accept",
		"accept-language",
		"cookie",
		"referer",
	}

	ctx, md := metadata.NewContext(req.Context())
	md.OrderedHTTP1Headers = ordered
	req = req.WithContext(ctx)

	hj := NewJA4HFingerprintHeaderInjector("ja4h")
	got, err := hj.GetHeaderValue(req)
	if err != nil {
		t.Fatal(err)
	}
	want := "ge11cr04fr00_171d872ea17d_ca8064b27201_5c8e7d6b8092"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestJA4HHeaderInjectorHTTP2(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Host = "example.com"
	req.Header.Set("Host", "example.com")
	req.Header.Set("User-Agent", "curl/8.7.1")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "fr")
	req.Header.Set("Cookie", "SID=123; theme=dark")
	req.Header.Set("Referer", "https://example.com/start")

	ctx, md := metadata.NewContext(req.Context())
	md.HTTP2Frames.Headers = []metadata.HeaderField{
		{Name: "host"},
		{Name: "user-agent"},
		{Name: "accept"},
		{Name: "accept-language"},
		{Name: "cookie"},
		{Name: "referer"},
	}
	req = req.WithContext(ctx)

	hj := NewJA4HFingerprintHeaderInjector("ja4h")
	got, err := hj.GetHeaderValue(req)
	if err != nil {
		t.Fatal(err)
	}
	want := "ge20cr04fr00_171d872ea17d_ca8064b27201_5c8e7d6b8092"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestJA4HHeaderInjectorHTTP2MultipleHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Host = "example.com"
	req.Header.Set("Host", "example.com")
	req.Header.Set("User-Agent", "curl/8.7.1")
	req.Header.Set("Accept", "*/*")
	req.Header.Add("Cookie", "SID=1")
	req.Header.Add("Cookie", "SID=2; theme=dark")

	ctx, md := metadata.NewContext(req.Context())
	md.HTTP2Frames.Headers = []metadata.HeaderField{
		{Name: "host"},
		{Name: "user-agent"},
		{Name: "accept"},
		{Name: "cookie"},
		{Name: "cookie"},
	}
	req = req.WithContext(ctx)

	hj := NewJA4HFingerprintHeaderInjector("ja4h")
	got, err := hj.GetHeaderValue(req)
	if err != nil {
		t.Fatal(err)
	}
	want := "ge20cn030000_042112399351_9d6f7e01e35f_09672c2b113f"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}
