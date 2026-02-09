package mobile

import (
	"net"
	"sync"
	"time"
)

// BroadcastUDPConn wraps a single UDP socket and broadcasts every query to all
// resolvers. The first response wins — this maximizes reliability during
// internet shutdowns where some resolvers may be blocked.
type BroadcastUDPConn struct {
	conn  *net.UDPConn
	addrs []*net.UDPAddr
}

// NewBroadcastUDPConn creates a single UDP socket that sends to all resolvers.
func NewBroadcastUDPConn(addrs []*net.UDPAddr) (*BroadcastUDPConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &BroadcastUDPConn{conn: conn, addrs: addrs}, nil
}

func (b *BroadcastUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return b.conn.ReadFrom(p)
}

func (b *BroadcastUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	var n int
	for _, addr := range b.addrs {
		nn, err := b.conn.WriteTo(p, addr)
		if err == nil {
			n = nn
		}
	}
	return n, nil
}

func (b *BroadcastUDPConn) Close() error                       { return b.conn.Close() }
func (b *BroadcastUDPConn) LocalAddr() net.Addr                { return b.conn.LocalAddr() }
func (b *BroadcastUDPConn) SetDeadline(t time.Time) error      { return b.conn.SetDeadline(t) }
func (b *BroadcastUDPConn) SetReadDeadline(t time.Time) error  { return b.conn.SetReadDeadline(t) }
func (b *BroadcastUDPConn) SetWriteDeadline(t time.Time) error { return b.conn.SetWriteDeadline(t) }

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

// MultiPacketConn multiplexes across multiple net.PacketConn transports (for DoT).
// It broadcasts writes and aggregates reads via a shared channel.
type MultiPacketConn struct {
	transports []net.PacketConn
	addrs      []net.Addr
	recvCh     chan recvMsg
	closeCh    chan struct{}
	closeOnce  sync.Once
}

type recvMsg struct {
	data []byte
	addr net.Addr
}

func NewMultiPacketConn(transports []net.PacketConn, addrs []net.Addr) *MultiPacketConn {
	m := &MultiPacketConn{
		transports: transports,
		addrs:      addrs,
		recvCh:     make(chan recvMsg, 256),
		closeCh:    make(chan struct{}),
	}
	for _, t := range transports {
		go m.recvLoop(t)
	}
	return m
}

func (m *MultiPacketConn) recvLoop(transport net.PacketConn) {
	for {
		buf := make([]byte, 4096)
		n, addr, err := transport.ReadFrom(buf)
		if err != nil {
			return
		}
		msg := recvMsg{data: make([]byte, n), addr: addr}
		copy(msg.data, buf[:n])
		select {
		case m.recvCh <- msg:
		case <-m.closeCh:
			return
		}
	}
}

func (m *MultiPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	msg, ok := <-m.recvCh
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(p, msg.data), msg.addr, nil
}

func (m *MultiPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	var n int
	for i, t := range m.transports {
		nn, err := t.WriteTo(p, m.addrs[i])
		if err == nil {
			n = nn
		}
	}
	return n, nil
}

func (m *MultiPacketConn) Close() error {
	m.closeOnce.Do(func() {
		close(m.closeCh)
		for _, t := range m.transports {
			t.Close()
		}
		close(m.recvCh)
	})
	return nil
}

func (m *MultiPacketConn) LocalAddr() net.Addr                { return m.transports[0].LocalAddr() }
func (m *MultiPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *MultiPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MultiPacketConn) SetWriteDeadline(t time.Time) error { return nil }
