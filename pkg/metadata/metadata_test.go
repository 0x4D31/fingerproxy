package metadata

import (
	"reflect"
	"testing"
)

func TestMetadataOrderedHeadersHTTP1(t *testing.T) {
	md := &Metadata{
		OrderedHTTP1Headers: []string{"host", "user-agent"},
		HTTP2Frames: HTTP2FingerprintingFrames{
			Headers: []HeaderField{{Name: "accept"}},
		},
	}
	got := md.OrderedHeaders()
	want := []string{"host", "user-agent"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestMetadataOrderedHeadersHTTP2(t *testing.T) {
	md := &Metadata{
		HTTP2Frames: HTTP2FingerprintingFrames{
			Headers: []HeaderField{
				{Name: ":method"},
				{Name: "User-Agent"},
				{Name: "accept"},
			},
		},
	}
	got := md.OrderedHeaders()
	want := []string{"user-agent", "accept"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}
