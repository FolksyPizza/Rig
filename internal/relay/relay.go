// Package relay multiplexes TCP streams over a single byte stream.
//
// Rig uses it for host passthrough: the gateway container accepts connections
// from the sandbox on a fixed port and carries each one over its own stdio to
// the rig process on the host, which connects to the matching local service.
// No container gets a network route to the host. The host side decides what
// each port number maps to from its own configuration, so the gateway cannot
// ask for an arbitrary host port.
//
// Frame format: type (1 byte) | stream id (4 bytes, big endian) |
// payload length (4 bytes, big endian) | payload.
//
// Standard library only: compiled into rig-helper inside an image build.
package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	frameOpen  byte = 1 // payload: 2-byte port index
	frameData  byte = 2
	frameClose byte = 3

	maxPayload   = 32 * 1024
	maxFrame     = 1 << 20
	maxBuffered  = 8 << 20 // per stream; a stream that falls further behind is cut
	maxStreams   = 256
	headerLength = 9
)

// ErrClosed is returned by operations on a closed session or stream.
var ErrClosed = errors.New("relay: closed")

// Session is one end of a multiplexed connection.
type Session struct {
	r io.Reader

	wmu sync.Mutex
	w   io.Writer

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	closed  bool
	done    chan struct{}

	// onOpen handles streams the remote end opens. Nil means remote opens
	// are refused (the gateway side only ever opens streams).
	onOpen func(index uint16, s *Stream)
}

// NewSession wraps a reader/writer pair. onOpen, if set, is called in its own
// goroutine for each stream the peer opens.
func NewSession(r io.Reader, w io.Writer, onOpen func(index uint16, s *Stream)) *Session {
	return &Session{r: r, w: w, streams: map[uint32]*Stream{}, done: make(chan struct{}), onOpen: onOpen}
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.done }

func (s *Session) writeFrame(typ byte, id uint32, payload []byte) error {
	var hdr [headerLength]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], id)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := s.w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// Run reads frames until the underlying reader ends or a protocol error
// occurs, then closes every stream.
func (s *Session) Run() error {
	defer s.shutdown()
	var hdr [headerLength]byte
	for {
		if _, err := io.ReadFull(s.r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		typ := hdr[0]
		id := binary.BigEndian.Uint32(hdr[1:5])
		n := binary.BigEndian.Uint32(hdr[5:9])
		if n > maxFrame {
			return fmt.Errorf("relay: frame of %d bytes exceeds limit", n)
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(s.r, payload); err != nil {
			return err
		}

		switch typ {
		case frameOpen:
			if s.onOpen == nil || len(payload) != 2 {
				_ = s.writeFrame(frameClose, id, nil)
				continue
			}
			st, ok := s.register(id)
			if !ok {
				_ = s.writeFrame(frameClose, id, nil)
				continue
			}
			go s.onOpen(binary.BigEndian.Uint16(payload), st)
		case frameData:
			if st := s.lookup(id); st != nil {
				st.deliver(payload)
			}
		case frameClose:
			if st := s.lookup(id); st != nil {
				st.remoteClose()
			}
		default:
			return fmt.Errorf("relay: unknown frame type %d", typ)
		}
	}
}

func (s *Session) register(id uint32) (*Stream, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.streams) >= maxStreams || s.streams[id] != nil {
		return nil, false
	}
	st := newStream(s, id)
	s.streams[id] = st
	return st, true
}

func (s *Session) lookup(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) forget(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *Session) shutdown() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	streams := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = map[uint32]*Stream{}
	s.mu.Unlock()
	for _, st := range streams {
		st.remoteClose()
	}
	close(s.done)
}

// Open starts a new stream to the peer's handler for the given port index.
func (s *Session) Open(index uint16) (*Stream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	if len(s.streams) >= maxStreams {
		s.mu.Unlock()
		return nil, errors.New("relay: too many streams")
	}
	s.nextID++
	id := s.nextID
	st := newStream(s, id)
	s.streams[id] = st
	s.mu.Unlock()

	var p [2]byte
	binary.BigEndian.PutUint16(p[:], index)
	if err := s.writeFrame(frameOpen, id, p[:]); err != nil {
		s.forget(id)
		return nil, err
	}
	return st, nil
}

// Stream is one multiplexed connection. It implements net.Conn; deadlines are
// accepted but not enforced.
type Stream struct {
	sess *Session
	id   uint32

	mu      sync.Mutex
	cond    *sync.Cond
	buf     []byte
	rclosed bool // peer closed or session ended
	lclosed bool // closed locally
}

func newStream(s *Session, id uint32) *Stream {
	st := &Stream{sess: s, id: id}
	st.cond = sync.NewCond(&st.mu)
	return st
}

func (st *Stream) deliver(p []byte) {
	st.mu.Lock()
	if st.lclosed || st.rclosed {
		st.mu.Unlock()
		return
	}
	if len(st.buf)+len(p) > maxBuffered {
		// The local reader stopped keeping up; cut this stream rather than
		// stall every other stream behind it.
		st.mu.Unlock()
		_ = st.Close()
		return
	}
	st.buf = append(st.buf, p...)
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) remoteClose() {
	st.mu.Lock()
	st.rclosed = true
	st.cond.Broadcast()
	st.mu.Unlock()
}

// Read implements io.Reader.
func (st *Stream) Read(p []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for len(st.buf) == 0 && !st.rclosed && !st.lclosed {
		st.cond.Wait()
	}
	if len(st.buf) > 0 {
		n := copy(p, st.buf)
		st.buf = st.buf[n:]
		return n, nil
	}
	if st.lclosed {
		return 0, ErrClosed
	}
	return 0, io.EOF
}

// Write implements io.Writer.
func (st *Stream) Write(p []byte) (int, error) {
	st.mu.Lock()
	closed := st.lclosed || st.rclosed
	st.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxPayload {
			n = maxPayload
		}
		if err := st.sess.writeFrame(frameData, st.id, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Close closes the stream in both directions.
func (st *Stream) Close() error {
	st.mu.Lock()
	if st.lclosed {
		st.mu.Unlock()
		return nil
	}
	st.lclosed = true
	st.cond.Broadcast()
	st.mu.Unlock()
	st.sess.forget(st.id)
	return st.sess.writeFrame(frameClose, st.id, nil)
}

func (st *Stream) LocalAddr() net.Addr                { return relayAddr{} }
func (st *Stream) RemoteAddr() net.Addr               { return relayAddr{} }
func (st *Stream) SetDeadline(t time.Time) error      { return nil }
func (st *Stream) SetReadDeadline(t time.Time) error  { return nil }
func (st *Stream) SetWriteDeadline(t time.Time) error { return nil }

type relayAddr struct{}

func (relayAddr) Network() string { return "relay" }
func (relayAddr) String() string  { return "relay" }

// Join copies between a and b until either side finishes, then closes both.
func Join(a, b io.ReadWriteCloser) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	go func() {
		_, _ = io.Copy(a, b)
		closeBoth()
	}()
	_, _ = io.Copy(b, a)
	closeBoth()
}
