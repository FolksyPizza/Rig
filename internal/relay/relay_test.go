package relay

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// pair connects two sessions back to back, the way the gateway's stdio is
// connected to the rig process.
func pair(t *testing.T, onOpen func(uint16, *Stream)) (gateway, host *Session) {
	t.Helper()
	g2hR, g2hW := io.Pipe()
	h2gR, h2gW := io.Pipe()
	gateway = NewSession(h2gR, g2hW, nil)
	host = NewSession(g2hR, h2gW, onOpen)
	go func() { _ = gateway.Run() }()
	go func() { _ = host.Run() }()
	t.Cleanup(func() {
		_ = g2hW.Close()
		_ = h2gW.Close()
	})
	return gateway, host
}

// echoServer accepts TCP connections and echoes what it reads.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln
}

// hostDialer maps port indexes to local addresses the way the rig process
// does: from its own table, never from the peer.
func hostDialer(table map[uint16]string) func(uint16, *Stream) {
	return func(index uint16, s *Stream) {
		addr, ok := table[index]
		if !ok {
			_ = s.Close()
			return
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			_ = s.Close()
			return
		}
		Join(s, c)
	}
}

func TestRoundTrip(t *testing.T) {
	ln := echoServer(t)
	gw, _ := pair(t, hostDialer(map[uint16]string{0: ln.Addr().String()}))

	st, err := gw.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Larger than one frame, so chunking is exercised.
	msg := make([]byte, 200*1024)
	_, _ = rand.Read(msg)
	go func() { _, _ = st.Write(msg) }()

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("echoed data differs")
	}
}

func TestUnknownIndexIsRefused(t *testing.T) {
	gw, _ := pair(t, hostDialer(map[uint16]string{}))
	st, err := gw.Open(7)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Errorf("read on refused stream = %v, want EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a stream to an unconfigured port was not closed")
	}
}

func TestPeerWithoutHandlerRefusesOpens(t *testing.T) {
	// The gateway side has no handler: the host side must not be able to
	// open streams into the gateway.
	g2hR, g2hW := io.Pipe()
	h2gR, h2gW := io.Pipe()
	gateway := NewSession(h2gR, g2hW, nil)
	host := NewSession(g2hR, h2gW, nil)
	go func() { _ = gateway.Run() }()
	go func() { _ = host.Run() }()
	defer g2hW.Close()
	defer h2gW.Close()

	st, err := host.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("open into a handler-less peer: read = %v, want EOF", err)
	}
}

func TestManyConcurrentStreams(t *testing.T) {
	ln := echoServer(t)
	gw, _ := pair(t, hostDialer(map[uint16]string{0: ln.Addr().String()}))

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := gw.Open(0)
			if err != nil {
				errs <- err
				return
			}
			defer st.Close()
			msg := bytes.Repeat([]byte{byte(i)}, 4096)
			if _, err := st.Write(msg); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(st, got); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, msg) {
				errs <- io.ErrUnexpectedEOF
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSessionEndClosesStreams(t *testing.T) {
	g2hR, g2hW := io.Pipe()
	h2gR, h2gW := io.Pipe()
	gw := NewSession(h2gR, g2hW, nil)
	go func() { _ = gw.Run() }()
	// Drain what the gateway writes so Open does not block.
	go func() { _, _ = io.Copy(io.Discard, g2hR) }()

	st, err := gw.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	_ = h2gW.Close() // the host side goes away
	if _, err := st.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("read after session end = %v, want EOF", err)
	}
	select {
	case <-gw.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("session did not report done")
	}
	if _, err := gw.Open(0); err == nil {
		t.Error("Open on an ended session should fail")
	}
}

func TestOversizedFrameEndsSession(t *testing.T) {
	r, w := io.Pipe()
	s := NewSession(r, io.Discard, nil)
	done := make(chan error, 1)
	go func() { done <- s.Run() }()
	// type=data, id=1, length = 2 MiB
	_, _ = w.Write([]byte{frameData, 0, 0, 0, 1, 0, 0x20, 0, 0})
	select {
	case err := <-done:
		if err == nil {
			t.Error("an oversized frame should be a protocol error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session kept running after an oversized frame")
	}
}
