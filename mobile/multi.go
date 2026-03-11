package mobile

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// deadTimeout is how long a resolver can go without responding (while
	// we are actively sending to it) before it is marked dead.
	// Kept short so dead resolvers are detected quickly and traffic shifts
	// to working ones within a few seconds.
	deadTimeout = 8 * time.Second
	// probeInterval is the minimum gap between sending probe traffic to a
	// dead resolver to check whether it has recovered.
	probeInterval = 15 * time.Second
	// healthCheckInterval is how often the background health loop runs.
	healthCheckInterval = 3 * time.Second
)

// resolverState tracks per-resolver health.
type resolverState struct {
	alive      bool
	lastSend   time.Time
	lastRecv   time.Time
	lastProbe  time.Time
	firstSend  time.Time // first query sent (zero until first WriteTo)
	everRecved bool      // true once any response has been received
}

// resolverTracker provides shared health-tracking logic for smart connectors.
// It maintains per-resolver state and picks the best resolver for each query.
type resolverTracker struct {
	mu       sync.Mutex
	states   []resolverState
	rrIndex  uint64 // round-robin counter (atomic)
	stopCh   chan struct{}
	stopOnce sync.Once
}

func newResolverTracker(n int) *resolverTracker {
	states := make([]resolverState, n)
	now := time.Now()
	for i := range states {
		states[i] = resolverState{
			alive:    true,
			lastRecv: now,
		}
	}
	t := &resolverTracker{
		states: states,
		stopCh: make(chan struct{}),
	}
	go t.healthLoop()
	return t
}

// pickBest selects one resolver index. It first checks for a dead resolver
// that is due for a probe (to discover recovery). Otherwise it round-robins
// among alive resolvers. If all are dead, it round-robins among all.
func (t *resolverTracker) pickBest() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	n := len(t.states)

	// Phase 1: look for a dead resolver due for a probe.
	for i := 0; i < n; i++ {
		s := &t.states[i]
		if !s.alive && now.Sub(s.lastProbe) >= probeInterval {
			s.lastProbe = now
			return i
		}
	}

	// Phase 2: round-robin among alive resolvers.
	start := int(atomic.AddUint64(&t.rrIndex, 1) - 1)
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		if t.states[idx].alive {
			return idx
		}
	}

	// Phase 3: all dead — round-robin among all (KCP handles retransmission).
	return start % n
}

func (t *resolverTracker) markSent(idx int) {
	t.mu.Lock()
	now := time.Now()
	t.states[idx].lastSend = now
	if t.states[idx].firstSend.IsZero() {
		t.states[idx].firstSend = now
	}
	t.mu.Unlock()
}

func (t *resolverTracker) markRecv(idx int) {
	t.mu.Lock()
	if !t.states[idx].alive {
		log.Printf("resolver %d recovered", idx)
	}
	t.states[idx].alive = true
	t.states[idx].everRecved = true
	t.states[idx].lastRecv = time.Now()
	t.mu.Unlock()
}

func (t *resolverTracker) markDead(idx int) {
	t.mu.Lock()
	if t.states[idx].alive {
		log.Printf("resolver %d marked dead", idx)
		t.states[idx].alive = false
	}
	t.mu.Unlock()
}

// healthLoop periodically checks for resolvers that have stopped responding.
func (t *resolverTracker) healthLoop() {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.checkHealth()
		case <-t.stopCh:
			return
		}
	}
}

func (t *resolverTracker) checkHealth() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for i := range t.states {
		s := &t.states[i]
		if !s.alive || s.lastSend.IsZero() {
			continue
		}
		// Fast path: if we've been sending for 3+ seconds and never got
		// a single response, mark dead immediately so traffic shifts to
		// working resolvers during initial connection.
		if !s.everRecved && !s.firstSend.IsZero() &&
			now.Sub(s.firstSend) > 3*time.Second {
			log.Printf("resolver %d marked dead (never responded, sent for %v)", i, now.Sub(s.firstSend).Round(time.Second))
			s.alive = false
			continue
		}
		// Normal path: resolver was previously responsive but stopped.
		if now.Sub(s.lastRecv) > deadTimeout &&
			now.Sub(s.lastSend) < deadTimeout {
			log.Printf("resolver %d marked dead (no response for %v)", i, now.Sub(s.lastRecv).Round(time.Second))
			s.alive = false
		}
	}
}

func (t *resolverTracker) close() {
	t.stopOnce.Do(func() { close(t.stopCh) })
}

// ---------------------------------------------------------------------------
// SmartUDPConn — replaces BroadcastUDPConn
// ---------------------------------------------------------------------------

// SmartUDPConn wraps a single UDP socket and routes each query to ONE resolver
// via health-tracking round-robin. Dead resolvers are periodically probed for
// recovery.
type SmartUDPConn struct {
	conn    *net.UDPConn
	addrs   []*net.UDPAddr
	addrMap map[string]int // IP:port → index for markRecv
	tracker *resolverTracker
}

// NewSmartUDPConn creates a smart UDP conn that distributes queries across resolvers.
func NewSmartUDPConn(addrs []*net.UDPAddr) (*SmartUDPConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	addrMap := make(map[string]int, len(addrs))
	for i, a := range addrs {
		addrMap[a.String()] = i
	}
	return &SmartUDPConn{
		conn:    conn,
		addrs:   addrs,
		addrMap: addrMap,
		tracker: newResolverTracker(len(addrs)),
	}, nil
}

func (s *SmartUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	idx := s.tracker.pickBest()
	s.tracker.markSent(idx)
	return s.conn.WriteTo(p, s.addrs[idx])
}

func (s *SmartUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := s.conn.ReadFrom(p)
	if err == nil {
		if idx, ok := s.addrMap[addr.String()]; ok {
			s.tracker.markRecv(idx)
		}
	}
	return n, addr, err
}

func (s *SmartUDPConn) Close() error {
	s.tracker.close()
	return s.conn.Close()
}

func (s *SmartUDPConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *SmartUDPConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *SmartUDPConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *SmartUDPConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// ---------------------------------------------------------------------------
// AddrNormConn — unchanged
// ---------------------------------------------------------------------------

// AddrNormConn wraps a net.PacketConn and overrides ReadFrom to always return
// a fixed address. This is needed because kcp-go filters incoming packets by
// comparing addr.String() to the remote address — when multiple resolvers are
// used, responses come from different IPs which KCP would silently drop.
type AddrNormConn struct {
	net.PacketConn
	fixedAddr net.Addr
}

func (a *AddrNormConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, err := a.PacketConn.ReadFrom(p)
	return n, a.fixedAddr, err
}

// ---------------------------------------------------------------------------
// SmartMultiPacketConn — replaces MultiPacketConn (for DoT)
// ---------------------------------------------------------------------------

type recvMsg struct {
	data []byte
	addr net.Addr
}

// SmartMultiPacketConn multiplexes across multiple net.PacketConn transports
// (for DoT). It routes each write to ONE transport via health-tracking
// round-robin and aggregates reads via a shared channel.
type SmartMultiPacketConn struct {
	transports []net.PacketConn
	addrs      []net.Addr
	recvCh     chan recvMsg
	closeCh    chan struct{}
	closeOnce  sync.Once
	tracker    *resolverTracker
}

func NewSmartMultiPacketConn(transports []net.PacketConn, addrs []net.Addr) *SmartMultiPacketConn {
	m := &SmartMultiPacketConn{
		transports: transports,
		addrs:      addrs,
		recvCh:     make(chan recvMsg, 256),
		closeCh:    make(chan struct{}),
		tracker:    newResolverTracker(len(transports)),
	}
	for i, t := range transports {
		go m.recvLoop(i, t)
	}
	return m
}

func (m *SmartMultiPacketConn) recvLoop(idx int, transport net.PacketConn) {
	for {
		buf := make([]byte, 4096)
		n, addr, err := transport.ReadFrom(buf)
		if err != nil {
			m.tracker.markDead(idx)
			return
		}
		m.tracker.markRecv(idx)
		msg := recvMsg{data: make([]byte, n), addr: addr}
		copy(msg.data, buf[:n])
		select {
		case m.recvCh <- msg:
		case <-m.closeCh:
			return
		}
	}
}

func (m *SmartMultiPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	msg, ok := <-m.recvCh
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(p, msg.data), msg.addr, nil
}

func (m *SmartMultiPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	idx := m.tracker.pickBest()
	m.tracker.markSent(idx)
	n, err := m.transports[idx].WriteTo(p, m.addrs[idx])
	if err != nil {
		m.tracker.markDead(idx)
		// Retry once with the next best resolver.
		idx2 := m.tracker.pickBest()
		if idx2 != idx {
			m.tracker.markSent(idx2)
			return m.transports[idx2].WriteTo(p, m.addrs[idx2])
		}
	}
	return n, err
}

func (m *SmartMultiPacketConn) Close() error {
	m.closeOnce.Do(func() {
		m.tracker.close()
		close(m.closeCh)
		for _, t := range m.transports {
			t.Close()
		}
		close(m.recvCh)
	})
	return nil
}

func (m *SmartMultiPacketConn) LocalAddr() net.Addr                { return m.transports[0].LocalAddr() }
func (m *SmartMultiPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *SmartMultiPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *SmartMultiPacketConn) SetWriteDeadline(t time.Time) error { return nil }
