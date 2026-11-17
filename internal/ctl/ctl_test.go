package ctl

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortDir avoids long t.TempDir paths, which can exceed the unix socket path limit.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func serve(t *testing.T, path string, h Handler) *Server {
	t.Helper()
	s, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(h)
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRoundTripAndErrors(t *testing.T) {
	path := filepath.Join(shortDir(t), "c.sock")
	serve(t, path, func(r Request) (any, error) {
		switch r.Op {
		case "echo":
			return r.Args, nil
		case "nodata":
			return nil, nil
		}
		return nil, errors.New("unknown op " + r.Op)
	})

	resp, err := Call(path, Request{Op: "echo", Args: []string{"a", "b"}})
	var got []string
	if err != nil || json.Unmarshal(resp.Data, &got) != nil || len(got) != 2 || got[1] != "b" {
		t.Fatalf("echo: %v %s %v", err, resp.Data, got)
	}
	if resp, err = Call(path, Request{Op: "nodata"}); err != nil || !resp.OK || len(resp.Data) != 0 {
		t.Fatalf("nodata: %v %+v", err, resp)
	}
	if _, err = Call(path, Request{Op: "bogus"}); err == nil || !strings.Contains(err.Error(), "unknown op bogus") {
		t.Fatalf("daemon error not returned: %v", err)
	}
}

func TestSocketIsPrivate(t *testing.T) {
	path := filepath.Join(shortDir(t), "c.sock")
	serve(t, path, func(Request) (any, error) { return nil, nil })
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v err %v, want 0600", fi.Mode().Perm(), err)
	}
}

func TestPeerUIDIsChecked(t *testing.T) {
	path := filepath.Join(shortDir(t), "c.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, _ := l.AcceptUnix()
		uid, err := peerUID(c)
		if err != nil || int(uid) != os.Getuid() {
			t.Errorf("peerUID=%d err=%v, want %d", uid, err, os.Getuid())
		}
		c.Close()
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c.Read(make([]byte, 1)) // wait for the server side to close
	c.Close()
}

func TestListenRefusesLiveSocketReplacesStale(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "c.sock")
	s := serve(t, path, func(Request) (any, error) { return nil, nil })
	if _, err := Listen(path); err == nil || !strings.Contains(err.Error(), "already listening") {
		t.Fatalf("second daemon accepted: %v", err)
	}
	s.l.SetUnlinkOnClose(false)
	s.l.Close() // simulate a crashed daemon: socket file remains, nobody listens
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale socket file missing: %v", err)
	}
	s2, err := Listen(path)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	s2.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("Close must remove the socket file")
	}
}

func TestPathTooLong(t *testing.T) {
	if _, err := Listen("/" + strings.Repeat("a", 120)); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("got %v", err)
	}
}

func TestCallWithoutDaemon(t *testing.T) {
	if _, err := Call(filepath.Join(shortDir(t), "none.sock"), Request{Op: "x"}); err == nil {
		t.Fatal("expected a dial error")
	}
}
