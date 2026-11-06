// Package netapi is ipamd's client of network-api's delegated-prefix routes (network-stack
// 2026-11-02-delegated-prefixes-design.md), called as the node's Bot with a key fetched from
// metadata for each request and never kept.
package netapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const DefaultBase = "https://network-api.ezghcloud.com"

// HTTPClient goes through no proxy and follows no redirect: the Bot's key goes to network-api only.
func HTTPClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("network-api redirects aren't followed") },
	}
}

var defaultHTTP = HTTPClient()

type Client struct {
	Base, Org, Project string
	Key                func(context.Context) (string, error) // called once per request
	HTTP               *http.Client
}

// Operation is a private address operation (`queued`, `running`, `succeeded`, `failed`); Address
// is the prefix.
type Operation struct {
	ID, Status, Address, Generation string
	RetryAfter                      time.Duration
}

// APIError is a refused request, or a failed operation's error (Status 0).
type APIError struct {
	Status        int
	Code, Message string
	RetryAfter    time.Duration
}

func (e *APIError) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("network operation failed: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("network-api answered %d %s: %s", e.Status, e.Code, e.Message)
}

func (c *Client) Assign(ctx context.Context, ni, family, idempotencyKey string) (Operation, error) {
	return c.post(ctx, ni, "assign", idempotencyKey, map[string]string{"family": family})
}

func (c *Client) Unassign(ctx context.Context, ni, family, prefix, expectedGeneration, idempotencyKey string) (Operation, error) {
	return c.post(ctx, ni, "unassign", idempotencyKey, map[string]string{"family": family, "prefix": prefix, "expectedGeneration": expectedGeneration})
}

// Operation reads an operation; a failed one answers its error as an *APIError beside it.
func (c *Client) Operation(ctx context.Context, id string) (Operation, error) {
	op, err := c.call(ctx, http.MethodGet, c.projectPath()+"/private-address-operations/"+url.PathEscape(id), "", nil)
	if err == nil && op.err != nil {
		return op.Operation, op.err
	}
	return op.Operation, err
}

func (c *Client) post(ctx context.Context, ni, verb, idempotencyKey string, body any) (Operation, error) {
	op, err := c.call(ctx, http.MethodPost, c.projectPath()+"/network-interfaces/"+url.PathEscape(ni)+"/private-prefixes/"+verb, idempotencyKey, body)
	return op.Operation, err
}

func (c *Client) projectPath() string {
	base := c.Base
	if base == "" {
		base = DefaultBase
	}
	return base + "/v1/organizations/" + url.PathEscape(c.Org) + "/projects/" + url.PathEscape(c.Project)
}

type answer struct {
	Operation
	err *APIError
}

func (c *Client) call(ctx context.Context, method, url, idempotencyKey string, body any) (answer, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return answer{}, err
	}
	key, err := c.Key(ctx)
	if err != nil {
		return answer{}, fmt.Errorf("the node's Bot key: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	hc := c.HTTP
	if hc == nil {
		hc = defaultHTTP
	}
	resp, err := hc.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return answer{}, err
	}
	retry := time.Duration(0)
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		retry = time.Duration(s) * time.Second
	}
	var doc struct {
		ID, Status, Address, Generation string
		Error                           *struct{ Code, Message string }
	}
	_ = json.Unmarshal(raw, &doc)
	if resp.StatusCode/100 != 2 {
		e := &APIError{Status: resp.StatusCode, RetryAfter: retry}
		if doc.Error != nil {
			e.Code, e.Message = doc.Error.Code, doc.Error.Message
		}
		return answer{}, e
	}
	a := answer{Operation: Operation{ID: doc.ID, Status: doc.Status, Address: doc.Address, Generation: doc.Generation, RetryAfter: retry}}
	if doc.ID == "" {
		return answer{}, fmt.Errorf("network-api answered %d without an operation", resp.StatusCode)
	}
	if doc.Status == "failed" {
		a.err = &APIError{}
		if doc.Error != nil {
			a.err.Code, a.err.Message = doc.Error.Code, doc.Error.Message
		}
	}
	return a, nil
}
