package httpcommon

import (
	"context"
	"net/url"
	"reflect"
	"testing"
)

func TestChromePseudoHeaderOrder(t *testing.T) {
	req := Request{
		Method: "GET",
		URL:    &url.URL{Scheme: "https", Host: "example.com", Path: "/p"},
		Header: make(map[string][]string),
	}
	var got []string
	_, err := EncodeHeaders(context.Background(), EncodeHeadersParam{
		Request:           req,
		ChromeFingerprint: true,
	}, func(name, value string) {
		if len(name) > 1 && name[0] == ':' {
			got = append(got, name)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{":method", ":authority", ":scheme", ":path"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pseudo order = %v, want %v", got, want)
	}
	t.Logf("pseudo order = %v OK", got)

	// default order must stay unchanged
	got = nil
	_, err = EncodeHeaders(context.Background(), EncodeHeadersParam{Request: req}, func(name, value string) {
		if len(name) > 1 && name[0] == ':' {
			got = append(got, name)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	wantDefault := []string{":authority", ":method", ":path", ":scheme"}
	if !reflect.DeepEqual(got, wantDefault) {
		t.Fatalf("default pseudo order = %v, want %v", got, wantDefault)
	}
	t.Logf("default pseudo order = %v OK", got)
}
