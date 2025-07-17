package ja4h

import (
	"net/http"
	"testing"
)

func TestExampleVector(t *testing.T) {
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

	got := FromRequest(req, ordered)
	want := "ge11cr04fr00_171d872ea17d_ca8064b27201_5c8e7d6b8092"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}
