package mobile

import (
	"log"
	"net"
	"sync"
	"time"
)

const (
	// deadTimeout is how long a resolver can go without responding (while
	// we are actively sending to it) before it is marked dead.
	// Set high enough to tolerate congested/high-latency networks common
	// in censored regions, while still detecting truly dead resolvers.
	deadTimeout = 12 * time.Second
	// fastDeadTimeout is how long a resolver that has NEVER responded can
	// keep sending before being marked dead. Higher than the health check
	// interval to tolerate slow initial handshakes on flaky networks.
	fastDeadTimeout = 6 * time.Second
	// probeInterval is the minimum gap between sending probe traffic to a
	// dead resolver to check whether it has recovered.
	probeInterval = 8 * time.Second
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

// ResolverMode controls how queries are distributed across resolvers.
type ResolverMode string

const (
	// ModeFanout sends each query to ALL alive resolvers (reliable, higher latency tolerance).
	ModeFanout ResolverMode = "fanout"
	// ModeRoundRobin sends each query to ONE alive resolver in rotation (faster, bandwidth aggregation).
	ModeRoundRobin ResolverMode = "roundrobin"
)

// resolverTracker provides shared health-tracking logic for smart connectors.
// It maintains per-resolver state and picks the best resolver for each query.
type resolverTracker struct {
	mu        sync.Mutex
	states    []resolverState
	rrIndex   int // round-robin cursor for primary in pickOne
	rrSecIdx  int // round-robin cursor for secondary in pickOne
	stopCh    chan struct{}
	stopOnce  sync.Once
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

// pickAlive returns all alive resolver indices plus any dead resolver that is
// due for a probe (to discover recovery). If all resolvers are dead and none
// are due for a probe, it returns all indices as a fallback.
func (t *resolverTracker) pickAlive() []int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	n := len(t.states)

	alive := make([]int, 0, n)
	for i := 0; i < n; i++ {
		if t.states[i].alive {
			alive = append(alive, i)
		} else if now.Sub(t.states[i].lastProbe) >= probeInterval {
			// Dead resolver due for a probe — include it.
			t.states[i].lastProbe = now
			alive = append(alive, i)
		}
	}

	// Fallback: all dead — return all indices (KCP handles retransmission).
	if len(alive) == 0 {
		alive = make([]int, n)
		for i := range alive {
			alive[i] = i
		}
	}
	return alive
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
		// Fast path: if we've been sending for fastDeadTimeout and never got
		// a single response, mark dead so traffic shifts to working resolvers.
		if !s.everRecved && !s.firstSend.IsZero() &&
			now.Sub(s.firstSend) > fastDeadTimeout {
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

// pickOne selects a primary alive resolver via round-robin and a secondary
// alive resolver via an independent cursor for fastest-wins redundancy.
// Returns primary and secondary indices (-1 if no secondary available).
func (t *resolverTracker) pickOne() (primary int, secondary int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	secondary = -1
	n := len(t.states)

	// Find primary alive resolver via round-robin.
	primary = -1
	for i := 0; i < n; i++ {
		idx := (t.rrIndex + i) % n
		if t.states[idx].alive {
			primary = idx
			t.rrIndex = (idx + 1) % n
			break
		}
	}
	if primary == -1 {
		primary = t.rrIndex % n
		t.rrIndex = (primary + 1) % n
	}

	// Find secondary alive resolver via its own cursor (skip primary).
	for i := 0; i < n; i++ {
		idx := (t.rrSecIdx + i) % n
		if idx != primary && t.states[idx].alive {
			secondary = idx
			t.rrSecIdx = (idx + 1) % n
			break
		}
	}

	// No alive secondary — probe a dead resolver instead.
	if secondary == -1 {
		now := time.Now()
		for i := 1; i < n; i++ {
			idx := (primary + i) % n
			if now.Sub(t.states[idx].lastProbe) >= probeInterval {
				t.states[idx].lastProbe = now
				secondary = idx
				break
			}
		}
	}

	return primary, secondary
}

// pickSpread selects up to maxTargets alive resolvers via round-robin for
// spread redundancy. If fewer than 2 alive resolvers are available, a dead
// resolver due for probing is included so recovery can be detected.
func (t *resolverTracker) pickSpread(maxTargets int) []int {
	t.mu.Lock()
	defer t.mu.Unlock()

	n := len(t.states)
	targets := make([]int, 0, maxTargets)

	// Pick alive resolvers via round-robin. Advance cursor by 1 so
	// successive calls start from different resolvers (bandwidth aggregation).
	for i := 0; i < n && len(targets) < maxTargets; i++ {
		idx := (t.rrIndex + i) % n
		if t.states[idx].alive {
			targets = append(targets, idx)
		}
	}
	if len(targets) > 0 {
		t.rrIndex = (targets[0] + 1) % n
	}

	// If we couldn't fill 2 targets, probe a dead resolver for recovery.
	if len(targets) < 2 {
		now := time.Now()
		for i := 0; i < n; i++ {
			idx := (t.rrIndex + i) % n
			if !t.states[idx].alive && now.Sub(t.states[idx].lastProbe) >= probeInterval {
				already := false
				for _, ti := range targets {
					if ti == idx {
						already = true
						break
					}
				}
				if !already {
					t.states[idx].lastProbe = now
					targets = append(targets, idx)
					break
				}
			}
		}
	}

	// Fallback: nothing found — use current cursor.
	if len(targets) == 0 {
		idx := t.rrIndex % n
		targets = append(targets, idx)
		t.rrIndex = (idx + 1) % n
	}

	return targets
}

func (t *resolverTracker) close() {
	t.stopOnce.Do(func() { close(t.stopCh) })
}

// ---------------------------------------------------------------------------
// SmartUDPConn — persistent socket, fan-out to all alive resolvers
// ---------------------------------------------------------------------------

// SmartUDPConn wraps a single UDP socket and distributes queries across
// resolvers. In fanout mode it sends to ALL alive resolvers (KCP deduplicates).
// In round-robin mode it sends to ONE alive resolver for bandwidth aggregation.
type SmartUDPConn struct {
	conn        *net.UDPConn
	addrs       []*net.UDPAddr
	addrMap     map[string]int // IP:port → index for markRecv
	tracker     *resolverTracker
	mode        ResolverMode
	spreadCount int // max targets in round-robin mode (default 3)
}

// NewSmartUDPConn creates a smart UDP conn that distributes queries across resolvers.
func NewSmartUDPConn(addrs []*net.UDPAddr, mode ResolverMode, spreadCount int) (*SmartUDPConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	addrMap := make(map[string]int, len(addrs))
	for i, a := range addrs {
		addrMap[a.String()] = i
	}
	if spreadCount < 1 {
		spreadCount = 3
	}
	return &SmartUDPConn{
		conn:        conn,
		addrs:       addrs,
		addrMap:     addrMap,
		tracker:     newResolverTracker(len(addrs)),
		mode:        mode,
		spreadCount: spreadCount,
	}, nil
}

func (s *SmartUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if s.mode == ModeRoundRobin {
		targets := s.tracker.pickSpread(s.spreadCount)
		s.tracker.markSent(targets[0])
		n, err := s.conn.WriteTo(p, s.addrs[targets[0]])
		for _, idx := range targets[1:] {
			s.tracker.markSent(idx)
			s.conn.WriteTo(p, s.addrs[idx]) // best-effort redundancy
		}
		return n, err
	}
	// Fanout: send to all alive resolvers.
	targets := s.tracker.pickAlive()
	var lastN int
	var lastErr error
	for _, idx := range targets {
		s.tracker.markSent(idx)
		n, err := s.conn.WriteTo(p, s.addrs[idx])
		if err != nil {
			lastErr = err
		} else {
			lastN = n
			lastErr = nil
		}
	}
	if lastErr == nil {
		return lastN, nil
	}
	return 0, lastErr
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
// AddrNormConn
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
// (for DoT). In fanout mode it sends to ALL alive transports (KCP deduplicates).
// In round-robin mode it sends to ONE alive transport for bandwidth aggregation.
type SmartMultiPacketConn struct {
	transports  []net.PacketConn
	addrs       []net.Addr
	recvCh      chan recvMsg
	closeCh     chan struct{}
	closeOnce   sync.Once
	recvWg      sync.WaitGroup
	tracker     *resolverTracker
	mode        ResolverMode
	spreadCount int // max targets in round-robin mode (default 3)
}

func NewSmartMultiPacketConn(transports []net.PacketConn, addrs []net.Addr, mode ResolverMode, spreadCount int) *SmartMultiPacketConn {
	if spreadCount < 1 {
		spreadCount = 3
	}
	m := &SmartMultiPacketConn{
		transports:  transports,
		addrs:       addrs,
		recvCh:      make(chan recvMsg, 256),
		closeCh:     make(chan struct{}),
		tracker:     newResolverTracker(len(transports)),
		mode:        mode,
		spreadCount: spreadCount,
	}
	m.recvWg.Add(len(transports))
	for i, t := range transports {
		go m.recvLoop(i, t)
	}
	return m
}

func (m *SmartMultiPacketConn) recvLoop(idx int, transport net.PacketConn) {
	defer m.recvWg.Done()
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
	if m.mode == ModeRoundRobin {
		targets := m.tracker.pickSpread(m.spreadCount)
		m.tracker.markSent(targets[0])
		n, err := m.transports[targets[0]].WriteTo(p, m.addrs[targets[0]])
		if err != nil {
			m.tracker.markDead(targets[0])
		}
		for _, idx := range targets[1:] {
			m.tracker.markSent(idx)
			if _, sErr := m.transports[idx].WriteTo(p, m.addrs[idx]); sErr != nil {
				m.tracker.markDead(idx)
			}
		}
		return n, err
	}
	// Fanout: send to all alive transports.
	targets := m.tracker.pickAlive()
	var lastN int
	var lastErr error
	for _, idx := range targets {
		m.tracker.markSent(idx)
		n, err := m.transports[idx].WriteTo(p, m.addrs[idx])
		if err != nil {
			m.tracker.markDead(idx)
			lastErr = err
		} else {
			lastN = n
			lastErr = nil
		}
	}
	if lastErr == nil {
		return lastN, nil
	}
	return 0, lastErr
}

func (m *SmartMultiPacketConn) Close() error {
	m.closeOnce.Do(func() {
		m.tracker.close()
		close(m.closeCh)
		// Close transports first so recvLoop's ReadFrom unblocks and exits.
		for _, t := range m.transports {
			t.Close()
		}
		// Wait for all recvLoops to exit before closing the channel,
		// preventing a send-on-closed-channel panic.
		m.recvWg.Wait()
		close(m.recvCh)
	})
	return nil
}

func (m *SmartMultiPacketConn) LocalAddr() net.Addr                { return m.transports[0].LocalAddr() }
func (m *SmartMultiPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *SmartMultiPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *SmartMultiPacketConn) SetWriteDeadline(t time.Time) error { return nil }
