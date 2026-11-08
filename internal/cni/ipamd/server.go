package ipamd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/ezgamehost/ezgh-cni/internal/cni/ipam"
)

// The socket API the plugin calls:
//
//	POST /v1/add {containerId, ifName, netns, namespace, pod} → {ipv4, ipv6, mtu, hostTable}
//	POST /v1/del {containerId, ifName}
//	GET  /v1/ready → 200 once the pod network is up, else 503
//
// Errors are {"error": {"code", "message"}}.
type AddRequest struct {
	ContainerID string `json:"containerId"`
	IfName      string `json:"ifName"`
	Netns       string `json:"netns"`
	Namespace   string `json:"namespace"`
	Pod         string `json:"pod"`
}

// AddResponse's HostTable is 100 + the private interface's deviceIndex.
type AddResponse struct {
	IPv4      netip.Addr `json:"ipv4"`
	IPv6      netip.Addr `json:"ipv6"`
	MTU       int        `json:"mtu"`
	HostTable int        `json:"hostTable"`
}

type request struct {
	kind  string // add, del, ready
	key   string
	reply chan reply
}

type reply struct {
	add   AddResponse
	ready bool
	err   error
}

func (d *daemon) serve(path string) (stop func(), err error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	ask := func(r *http.Request, kind, key string) reply {
		ch := make(chan reply, 1)
		select {
		case d.reqs <- request{kind: kind, key: key, reply: ch}:
		case <-r.Context().Done():
			return reply{err: r.Context().Err()}
		}
		select {
		case rep := <-ch:
			return rep
		case <-r.Context().Done():
			return reply{err: r.Context().Err()}
		}
	}
	keyOf := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		var in AddRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil || in.ContainerID == "" || in.IfName == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "containerId and ifName are required")
			return "", false
		}
		return in.ContainerID + "/" + in.IfName, true
	}
	mux.HandleFunc("POST /v1/add", func(w http.ResponseWriter, r *http.Request) {
		if key, ok := keyOf(w, r); ok {
			if rep := ask(r, "add", key); rep.err != nil {
				writeError(w, http.StatusServiceUnavailable, "no_address", rep.err.Error())
			} else {
				writeJSON(w, http.StatusOK, rep.add)
			}
		}
	})
	mux.HandleFunc("POST /v1/del", func(w http.ResponseWriter, r *http.Request) {
		if key, ok := keyOf(w, r); ok {
			if rep := ask(r, "del", key); rep.err != nil {
				writeError(w, http.StatusServiceUnavailable, "unavailable", rep.err.Error())
			} else {
				writeJSON(w, http.StatusOK, struct{}{})
			}
		}
	})
	mux.HandleFunc("GET /v1/ready", func(w http.ResponseWriter, r *http.Request) {
		if rep := ask(r, "ready", ""); rep.ready {
			writeJSON(w, http.StatusOK, map[string]bool{"ready": true})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]bool{"ready": false})
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}

func (d *daemon) handle(r request) {
	now := time.Now()
	switch r.kind {
	case "ready":
		r.reply <- reply{ready: d.known && d.conflist}
	case "del":
		d.pool.Release(r.key, now)
		// The runtime gave up on this container's ADD; never allocate for it later.
		keep := d.waiters[:0]
		for _, w := range d.waiters {
			if w.key == r.key {
				w.reply <- reply{err: errors.New("deleted")}
			} else {
				keep = append(keep, w)
			}
		}
		d.waiters = keep
		r.reply <- reply{err: d.save()}
	case "add":
		if !d.give(r.key, r.reply, now) {
			if f := d.lacking(); f != nil {
				r.reply <- reply{err: errors.New(f.message)}
				return
			}
			d.waiters = append(d.waiters, waiter{key: r.key, deadline: now.Add(d.o.Timing.AddWait), reply: r.reply})
		}
	}
}

// give answers an ADD when the pool has an address for it, kept on disk first.
func (d *daemon) give(key string, ch chan reply, now time.Time) bool {
	a, err := d.pool.Allocate(key, now)
	if err != nil {
		return false
	}
	if err := d.save(); err != nil {
		ch <- reply{err: err}
		return true
	}
	ch <- reply{add: AddResponse{IPv4: a.V4, IPv6: a.V6, MTU: d.iface.MTU, HostTable: d.table}}
	return true
}

// lacking is why the pool can't serve an ADD right now, when network refused to fill it.
func (d *daemon) lacking() *failure {
	if d.held6 == nil {
		return d.cause[ipv6]
	}
	return d.cause[ipv4]
}

func (d *daemon) serveWaiters(now time.Time) {
	keep := d.waiters[:0]
	for _, w := range d.waiters {
		switch {
		case d.give(w.key, w.reply, now):
		case d.lacking() != nil:
			w.reply <- reply{err: errors.New(d.lacking().message)}
		default:
			keep = append(keep, w)
		}
	}
	d.waiters = keep
}

func (d *daemon) expire(now time.Time) {
	keep := d.waiters[:0]
	for _, w := range d.waiters {
		if now.Before(w.deadline) {
			keep = append(keep, w)
		} else {
			w.reply <- reply{err: fmt.Errorf("no free address yet: no prefix realized within %s", d.o.Timing.AddWait)}
		}
	}
	d.waiters = keep
}

func (d *daemon) allocationsPath() string { return filepath.Join(d.o.Dir, "allocations.json") }

// saved is allocations.json: the pool's state and an unassign in flight, with its key.
type saved struct {
	ipam.State
	Unassign *pendingUnassign `json:"unassign"`
}

type pendingUnassign struct {
	ipam.Prefix
	Key string `json:"idempotencyKey"`
}

func (d *daemon) load() (saved, error) {
	var s saved
	b, err := os.ReadFile(d.allocationsPath())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("ipamd: %s: %w", d.allocationsPath(), err)
	}
	return s, nil
}

func (d *daemon) save() error {
	s := saved{State: d.pool.State()}
	if d.unassigning != nil {
		s.Unassign = &pendingUnassign{Prefix: *d.unassigning, Key: d.keys[unassign]}
	}
	b, _ := json.Marshal(s)
	return writeFile(d.allocationsPath(), b, 0o600)
}

// writeFile replaces path durably: a temporary file, fsync, rename, fsync of the directory.
func writeFile(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if err := errors.Join(err, f.Chmod(mode), f.Close()); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

// Client is the plugin's side of the socket.
type Client struct{ Socket string }

func (c Client) http() *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	}}}
}

func (c Client) Add(ctx context.Context, req AddRequest) (AddResponse, error) {
	var out AddResponse
	return out, c.call(ctx, http.MethodPost, "/v1/add", req, &out)
}

func (c Client) Del(ctx context.Context, containerID, ifName string) error {
	return c.call(ctx, http.MethodPost, "/v1/del", AddRequest{ContainerID: containerID, IfName: ifName}, nil)
}

func (c Client) Ready(ctx context.Context) bool {
	return c.call(ctx, http.MethodGet, "/v1/ready", nil, nil) == nil
}

func (c Client) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://ipamd"+path, body)
	if err != nil {
		return err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("ezgh-vpc-cni: ipamd at %s: %w", c.Socket, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct{ Message string } `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error.Message != "" {
			return fmt.Errorf("ezgh-vpc-cni: %s", e.Error.Message)
		}
		return fmt.Errorf("ezgh-vpc-cni: ipamd answered %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
