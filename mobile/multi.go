package mobile

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

const (
	// deadTimeout is how long a resolver can go without responding (while
	// we are actively sending to it) before it is marked dead.
	// Set high enough to tolerate congested/high-latency networks common
	// in censored regions, while still detecting truly dead resolvers.
	deadTimeout = 12 * time.Second
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
// SmartUDPConn — persistent socket, fan-out to all alive resolvers
// ---------------------------------------------------------------------------

// SmartUDPConn wraps a single UDP socket and fans out each query to ALL alive
// resolvers simultaneously. KCP deduplicates responses, so the fastest reply
// wins. Dead resolvers are periodically probed for recovery.
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
// PerQueryUDPConn — per-query fresh sockets with forged response filtering
// ---------------------------------------------------------------------------

const (
	// udpWorkers is the number of worker goroutines in the pool.
	// Each worker handles one query at a time on a fresh UDP socket.
	udpWorkers = 64
	// udpReadTimeout is how long a worker waits for a valid response
	// after sending a query. Must be long enough for a real response to
	// arrive after skipping forged injections, but short enough that
	// stale workers don't accumulate.
	udpReadTimeout = 1500 * time.Millisecond
)

// ForgedStats tracks censorship-injected DNS responses.
type ForgedStats struct {
	SERVFAIL int64
	NXDOMAIN int64
	Other    int64
	Valid    int64
}

// udpWork is a unit of work for a per-query UDP worker.
type udpWork struct {
	payload []byte
	addr    *net.UDPAddr
	idx     int // resolver index for health tracking
}

// udpResponse is a valid response from a per-query UDP worker.
type udpResponse struct {
	data []byte
	n    int
	addr net.Addr
}

// PerQueryUDPConn creates a fresh UDP socket for every outgoing DNS query,
// randomizing source ports to defeat fingerprinting by source-port correlation.
// Each worker also filters forged responses (SERVFAIL/NXDOMAIN injections)
// by reading in a loop until a valid response arrives or timeout.
type PerQueryUDPConn struct {
	addrs   []*net.UDPAddr
	addrMap map[string]int
	tracker *resolverTracker

	workCh    chan udpWork
	recvCh    chan udpResponse
	closeCh   chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	// Forged response counters (atomic).
	forgedSERVFAIL int64
	forgedNXDOMAIN int64
	forgedOther    int64
	validCount     int64
}

// NewPerQueryUDPConn creates a per-query UDP conn with a worker pool.
func NewPerQueryUDPConn(addrs []*net.UDPAddr) *PerQueryUDPConn {
	addrMap := make(map[string]int, len(addrs))
	for i, a := range addrs {
		addrMap[a.String()] = i
	}
	s := &PerQueryUDPConn{
		addrs:   addrs,
		addrMap: addrMap,
		tracker: newResolverTracker(len(addrs)),
		workCh:  make(chan udpWork, 256),
		recvCh:  make(chan udpResponse, 256),
		closeCh: make(chan struct{}),
	}
	s.wg.Add(udpWorkers)
	for i := 0; i < udpWorkers; i++ {
		go s.worker()
	}
	return s
}

// worker processes send-and-receive jobs on fresh UDP sockets.
func (s *PerQueryUDPConn) worker() {
	defer s.wg.Done()
	for {
		select {
		case work, ok := <-s.workCh:
			if !ok {
				return
			}
			s.handleQuery(work)
		case <-s.closeCh:
			return
		}
	}
}

// handleQuery sends a DNS query on a fresh socket and reads responses,
// skipping forged injections (SERVFAIL/NXDOMAIN) until a valid response
// arrives or the deadline expires.
func (s *PerQueryUDPConn) handleQuery(work udpWork) {
	conn, err := net.DialUDP("udp", nil, work.addr)
	if err != nil {
		return
	}
	defer conn.Close()

	_, err = conn.Write(work.payload)
	if err != nil {
		return
	}

	deadline := time.Now().Add(udpReadTimeout)
	conn.SetReadDeadline(deadline)
	var buf [4096]byte

	for {
		n, err := conn.Read(buf[:])
		if err != nil {
			return
		}

		if n >= 4 {
			rcode := int(buf[3]) & 0x0f
			switch rcode {
			case dns.RcodeServerFailure:
				atomic.AddInt64(&s.forgedSERVFAIL, 1)
				continue // skip forged injection, wait for real response
			case dns.RcodeNameError:
				atomic.AddInt64(&s.forgedNXDOMAIN, 1)
				continue // skip forged injection, wait for real response
			case dns.RcodeNoError:
				atomic.AddInt64(&s.validCount, 1)
			default:
				atomic.AddInt64(&s.forgedOther, 1)
			}
		}

		s.tracker.markRecv(work.idx)

		resp := udpResponse{
			data: make([]byte, n),
			n:    n,
			addr: work.addr,
		}
		copy(resp.data, buf[:n])

		select {
		case s.recvCh <- resp:
		case <-s.closeCh:
		}
		return
	}
}

func (s *PerQueryUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	targets := s.tracker.pickAlive()
	for _, idx := range targets {
		s.tracker.markSent(idx)
		// Copy payload — workers may run concurrently after we return.
		payload := make([]byte, len(p))
		copy(payload, p)
		select {
		case s.workCh <- udpWork{payload: payload, addr: s.addrs[idx], idx: idx}:
		case <-s.closeCh:
			return 0, net.ErrClosed
		}
	}
	return len(p), nil
}

func (s *PerQueryUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case resp, ok := <-s.recvCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		return copy(p, resp.data), resp.addr, nil
	case <-s.closeCh:
		return 0, nil, net.ErrClosed
	}
}

func (s *PerQueryUDPConn) Close() error {
	s.closeOnce.Do(func() {
		s.tracker.close()
		close(s.closeCh)
		s.wg.Wait()
		close(s.recvCh)
	})
	return nil
}

// ForgedResponseStats returns a snapshot of forged response counters.
func (s *PerQueryUDPConn) ForgedResponseStats() ForgedStats {
	return ForgedStats{
		SERVFAIL: atomic.LoadInt64(&s.forgedSERVFAIL),
		NXDOMAIN: atomic.LoadInt64(&s.forgedNXDOMAIN),
		Other:    atomic.LoadInt64(&s.forgedOther),
		Valid:    atomic.LoadInt64(&s.validCount),
	}
}

func (s *PerQueryUDPConn) LocalAddr() net.Addr                { return nil }
func (s *PerQueryUDPConn) SetDeadline(t time.Time) error      { return nil }
func (s *PerQueryUDPConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *PerQueryUDPConn) SetWriteDeadline(t time.Time) error { return nil }

// ---------------------------------------------------------------------------
// SinglePerQueryUDPConn — per-query sockets for a single resolver
// ---------------------------------------------------------------------------

// SinglePerQueryUDPConn is like PerQueryUDPConn but for a single resolver.
// Avoids the overhead of multi-resolver health tracking.
type SinglePerQueryUDPConn struct {
	addr      *net.UDPAddr
	workCh    chan []byte
	recvCh    chan udpResponse
	closeCh   chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	forgedSERVFAIL int64
	forgedNXDOMAIN int64
	forgedOther    int64
	validCount     int64
}

// NewSinglePerQueryUDPConn creates a per-query UDP conn for a single resolver.
func NewSinglePerQueryUDPConn(addr *net.UDPAddr) *SinglePerQueryUDPConn {
	s := &SinglePerQueryUDPConn{
		addr:    addr,
		workCh:  make(chan []byte, 256),
		recvCh:  make(chan udpResponse, 256),
		closeCh: make(chan struct{}),
	}
	s.wg.Add(udpWorkers)
	for i := 0; i < udpWorkers; i++ {
		go s.worker()
	}
	return s
}

func (s *SinglePerQueryUDPConn) worker() {
	defer s.wg.Done()
	for {
		select {
		case payload, ok := <-s.workCh:
			if !ok {
				return
			}
			s.handleQuery(payload)
		case <-s.closeCh:
			return
		}
	}
}

func (s *SinglePerQueryUDPConn) handleQuery(payload []byte) {
	conn, err := net.DialUDP("udp", nil, s.addr)
	if err != nil {
		return
	}
	defer conn.Close()

	_, err = conn.Write(payload)
	if err != nil {
		return
	}

	deadline := time.Now().Add(udpReadTimeout)
	conn.SetReadDeadline(deadline)
	var buf [4096]byte

	for {
		n, err := conn.Read(buf[:])
		if err != nil {
			return
		}

		if n >= 4 {
			rcode := int(buf[3]) & 0x0f
			switch rcode {
			case dns.RcodeServerFailure:
				atomic.AddInt64(&s.forgedSERVFAIL, 1)
				continue // skip forged injection
			case dns.RcodeNameError:
				atomic.AddInt64(&s.forgedNXDOMAIN, 1)
				continue // skip forged injection
			case dns.RcodeNoError:
				atomic.AddInt64(&s.validCount, 1)
			default:
				atomic.AddInt64(&s.forgedOther, 1)
			}
		}

		resp := udpResponse{
			data: make([]byte, n),
			n:    n,
			addr: s.addr,
		}
		copy(resp.data, buf[:n])
		select {
		case s.recvCh <- resp:
		case <-s.closeCh:
		}
		return
	}
}

func (s *SinglePerQueryUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	payload := make([]byte, len(p))
	copy(payload, p)
	select {
	case s.workCh <- payload:
		return len(p), nil
	case <-s.closeCh:
		return 0, net.ErrClosed
	}
}

func (s *SinglePerQueryUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case resp, ok := <-s.recvCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		return copy(p, resp.data), resp.addr, nil
	case <-s.closeCh:
		return 0, nil, net.ErrClosed
	}
}

func (s *SinglePerQueryUDPConn) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
		s.wg.Wait()
		close(s.recvCh)
	})
	return nil
}

func (s *SinglePerQueryUDPConn) LocalAddr() net.Addr                { return nil }
func (s *SinglePerQueryUDPConn) SetDeadline(t time.Time) error      { return nil }
func (s *SinglePerQueryUDPConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *SinglePerQueryUDPConn) SetWriteDeadline(t time.Time) error { return nil }

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
// (for DoT). It fans out each write to ALL alive transports simultaneously
// and aggregates reads via a shared channel. KCP deduplicates responses.
type SmartMultiPacketConn struct {
	transports []net.PacketConn
	addrs      []net.Addr
	recvCh     chan recvMsg
	closeCh    chan struct{}
	closeOnce  sync.Once
	recvWg     sync.WaitGroup
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
