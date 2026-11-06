package netapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type seen struct {
	method, path, body, key, auth string
}

func fake(t *testing.T, status int, header map[string]string, body string) (*Client, *[]seen, *int) {
	var reqs []seen
	keys := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		reqs = append(reqs, seen{r.Method, r.URL.Path, string(b), r.Header.Get("Idempotency-Key"), r.Header.Get("Authorization")})
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(ts.Close)
	c := &Client{Base: ts.URL, Org: "org-uuid", Project: "prj-uuid", Key: func(context.Context) (string, error) {
		keys++
		return fmt.Sprintf("ezgh_key%d", keys), nil
	}}
	return c, &reqs, &keys
}

const op = `{"id":"op1","status":"queued","address":"","generation":"0","error":null}`

func TestAssignBody(t *testing.T) {
	c, reqs, _ := fake(t, 202, map[string]string{"Retry-After": "2"}, op)
	got, err := c.Assign(context.Background(), "eni_x", "ipv4", "k1")
	if err != nil || got.ID != "op1" || got.Status != "queued" || got.RetryAfter != 2*time.Second {
		t.Fatal(got, err)
	}
	if (*reqs)[0].body != `{"family":"ipv4"}` || (*reqs)[0].method != "POST" {
		t.Fatalf("%+v", (*reqs)[0])
	}
}

func TestUnassignBody(t *testing.T) {
	c, reqs, _ := fake(t, 202, nil, op)
	if _, err := c.Unassign(context.Background(), "eni_x", "ipv4", "10.0.1.16/28", "7", "k2"); err != nil {
		t.Fatal(err)
	}
	if b := (*reqs)[0].body; b != `{"expectedGeneration":"7","family":"ipv4","prefix":"10.0.1.16/28"}` {
		t.Fatal(b)
	}
	if !strings.HasSuffix((*reqs)[0].path, "/network-interfaces/eni_x/private-prefixes/unassign") {
		t.Fatal((*reqs)[0].path)
	}
}

func TestIdempotencyKeySent(t *testing.T) {
	c, reqs, _ := fake(t, 202, nil, op)
	c.Assign(context.Background(), "eni_x", "ipv6", "intent-1")
	c.Assign(context.Background(), "eni_x", "ipv6", "intent-1")
	if (*reqs)[0].key != "intent-1" || (*reqs)[1].key != "intent-1" {
		t.Fatalf("%+v", *reqs)
	}
}

func TestPathUsesOrgAndProject(t *testing.T) {
	c, reqs, _ := fake(t, 200, nil, op)
	c.Assign(context.Background(), "eni_x", "ipv4", "k")
	c.Operation(context.Background(), "op1")
	if p := (*reqs)[0].path; p != "/v1/organizations/org-uuid/projects/prj-uuid/network-interfaces/eni_x/private-prefixes/assign" {
		t.Fatal(p)
	}
	if p := (*reqs)[1].path; p != "/v1/organizations/org-uuid/projects/prj-uuid/private-address-operations/op1" || (*reqs)[1].method != "GET" {
		t.Fatal(p)
	}
}

func TestKeyPerRequest(t *testing.T) {
	c, reqs, keys := fake(t, 202, nil, op)
	for range 3 {
		c.Assign(context.Background(), "eni_x", "ipv4", "k")
	}
	if *keys != 3 || (*reqs)[2].auth != "Bearer ezgh_key3" {
		t.Fatal(*keys, (*reqs)[2].auth)
	}
}

func TestErrorDecoded(t *testing.T) {
	c, _, _ := fake(t, 409, nil, `{"error":{"code":"prefix_unavailable","message":"The subnet has no free aligned block of this size"}}`)
	_, err := c.Assign(context.Background(), "eni_x", "ipv4", "k")
	var e *APIError
	if !errors.As(err, &e) || e.Status != 409 || e.Code != "prefix_unavailable" || e.Message == "" {
		t.Fatal(err)
	}
}

func TestFailedOperationIsAPIError(t *testing.T) {
	c, _, _ := fake(t, 200, nil, `{"id":"op1","status":"failed","error":{"code":"prefix_unavailable","message":"gone"}}`)
	got, err := c.Operation(context.Background(), "op1")
	var e *APIError
	if !errors.As(err, &e) || e.Code != "prefix_unavailable" || got.Status != "failed" {
		t.Fatal(got, err)
	}
}

func Test429RetryAfter(t *testing.T) {
	c, _, _ := fake(t, 429, map[string]string{"Retry-After": "17"}, `{"error":{"code":"rate_limited","message":"slow down"}}`)
	_, err := c.Assign(context.Background(), "eni_x", "ipv4", "k")
	var e *APIError
	if !errors.As(err, &e) || e.Status != 429 || e.RetryAfter != 17*time.Second {
		t.Fatal(err)
	}
}

func TestNoKeyInErrors(t *testing.T) {
	for _, status := range []int{403, 500} {
		c, _, _ := fake(t, status, nil, `{"error":{"code":"x","message":"y"}}`)
		_, err := c.Assign(context.Background(), "eni_x", "ipv4", "k")
		if err == nil || strings.Contains(err.Error(), "ezgh_") {
			t.Fatal(err)
		}
	}
	c := &Client{Base: "http://127.0.0.1:1", Key: func(context.Context) (string, error) { return "ezgh_secret", nil }}
	if _, err := c.Assign(context.Background(), "eni_x", "ipv4", "k"); err == nil || strings.Contains(err.Error(), "ezgh_") {
		t.Fatal(err)
	}
}

func TestNoProxyNoRedirects(t *testing.T) {
	c, reqs, _ := fake(t, 302, map[string]string{"Location": "/v1/elsewhere"}, "")
	if _, err := c.Assign(context.Background(), "eni_x", "ipv4", "k"); err == nil || len(*reqs) != 1 {
		t.Fatalf("%v after %d requests", err, len(*reqs))
	}
	if HTTPClient().Transport.(*http.Transport).Proxy != nil {
		t.Fatal("the transport has a proxy")
	}
}
