// Package mobile provides a gomobile-compatible API for the DNSTT client.
//
// It supports three DNS transport modes, auto-detected from the dnsAddr
// parameter passed to NewClient:
//
//   - "https://..." → DoH (DNS over HTTPS) with HTTP/2 and uTLS fingerprinting
//   - "tls://host:port" → DoT (DNS over TLS) with uTLS fingerprinting
//   - "host:port" → plain UDP DNS
package mobile

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	dnsttclient "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// Default uTLS fingerprint distribution (matches upstream default).
const defaultUTLSDistribution = "4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13"

// numPadding matches the constant in dnstt-client/lib/dns.go.
const numPadding = 3

// DnsttClient wraps a DNSTT tunnel client with Start/Stop lifecycle.
type DnsttClient struct {
	dnsAddr      string
	tunnelDomain string
	pubkey       []byte
	listenAddr   string

	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
	listener net.Listener
}

// NewClient creates a new DNSTT client. Transport is auto-detected from dnsAddr:
//
//   - "https://..." → DoH (HTTP/2 + uTLS fingerprint)
//   - "tls://host:port" → DoT (TLS + uTLS fingerprint)
//   - "host:port" → UDP
func NewClient(dnsAddr, tunnelDomain, publicKey, listenAddr string) (*DnsttClient, error) {
	if tunnelDomain == "" {
		return nil, fmt.Errorf("tunnel domain is required")
	}
	if publicKey == "" {
		return nil, fmt.Errorf("public key is required")
	}
	if listenAddr == "" {
		return nil, fmt.Errorf("listen address is required")
	}

	pubkey, err := noise.DecodeKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %v", err)
	}

	return &DnsttClient{
		dnsAddr:      dnsAddr,
		tunnelDomain: tunnelDomain,
		pubkey:       pubkey,
		listenAddr:   listenAddr,
	}, nil
}

// Start begins the DNSTT tunnel in a background goroutine.
func (c *DnsttClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("client is already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel

	// Parse the tunnel domain.
	domain, err := dns.ParseName(c.tunnelDomain)
	if err != nil {
		cancel()
		return fmt.Errorf("invalid tunnel domain: %v", err)
	}

	// Sample uTLS fingerprint.
	utlsID, err := dnsttclient.SampleUTLSDistribution(defaultUTLSDistribution)
	if err != nil {
		cancel()
		return fmt.Errorf("sampling uTLS distribution: %v", err)
	}
	if utlsID != nil {
		log.Printf("uTLS fingerprint %s %s", utlsID.Client, utlsID.Version)
	}

	// Create transport based on address prefix.
	// dnsAddr may be comma-separated for multi-resolver support (UDP/DoT only).
	var remoteAddr net.Addr
	var pconn net.PacketConn

	switch {
	case strings.HasPrefix(c.dnsAddr, "https://"):
		// DoH — HTTP/2 with uTLS fingerprint camouflage (single URL only).
		var rt http.RoundTripper
		if utlsID == nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			rt = transport
		} else {
			rt = dnsttclient.NewUTLSRoundTripper(nil, utlsID)
		}
		pconn, err = dnsttclient.NewHTTPPacketConn(rt, c.dnsAddr, 32)
		if err != nil {
			cancel()
			return fmt.Errorf("creating DoH transport: %v", err)
		}
		remoteAddr = turbotunnel.DummyAddr{}

	case strings.Contains(c.dnsAddr, "tls://"):
		// DoT — TLS with uTLS fingerprint camouflage.
		// May be comma-separated for multi-resolver (e.g. "tls://1.1.1.1:853,tls://8.8.8.8:853").
		var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if utlsID == nil {
			dialTLSContext = (&tls.Dialer{}).DialContext
		} else {
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return utlsDialContext(ctx, network, addr, nil, utlsID)
			}
		}

		addrs := strings.Split(c.dnsAddr, ",")
		if len(addrs) == 1 {
			// Single resolver — no MultiPacketConn overhead.
			dotAddr := strings.TrimPrefix(strings.TrimSpace(addrs[0]), "tls://")
			pconn, err = dnsttclient.NewTLSPacketConn(dotAddr, dialTLSContext)
			if err != nil {
				cancel()
				return fmt.Errorf("creating DoT transport: %v", err)
			}
		} else {
			// Multiple resolvers — create a transport per address.
			var transports []net.PacketConn
			var tAddrs []net.Addr
			for _, a := range addrs {
				dotAddr := strings.TrimPrefix(strings.TrimSpace(a), "tls://")
				t, tErr := dnsttclient.NewTLSPacketConn(dotAddr, dialTLSContext)
				if tErr != nil {
					// Close any already-created transports.
					for _, prev := range transports {
						prev.Close()
					}
					cancel()
					return fmt.Errorf("creating DoT transport for %s: %v", dotAddr, tErr)
				}
				transports = append(transports, t)
				tAddrs = append(tAddrs, turbotunnel.DummyAddr{})
			}
			pconn = NewMultiPacketConn(transports, tAddrs)
			log.Printf("multi-resolver DoT: %d transports", len(transports))
		}
		remoteAddr = turbotunnel.DummyAddr{}

	default:
		// Plain UDP — may be comma-separated for multi-resolver.
		addrs := strings.Split(c.dnsAddr, ",")
		if len(addrs) == 1 {
			// Single resolver — original behavior, no wrapping.
			remoteAddr, err = net.ResolveUDPAddr("udp", strings.TrimSpace(addrs[0]))
			if err != nil {
				cancel()
				return fmt.Errorf("resolving UDP address: %v", err)
			}
			pconn, err = net.ListenUDP("udp", nil)
			if err != nil {
				cancel()
				return fmt.Errorf("opening UDP socket: %v", err)
			}
		} else {
			// Multiple resolvers — broadcast every query to all, first response wins.
			var udpAddrs []*net.UDPAddr
			for _, a := range addrs {
				addr, rErr := net.ResolveUDPAddr("udp", strings.TrimSpace(a))
				if rErr != nil {
					cancel()
					return fmt.Errorf("resolving UDP address %s: %v", a, rErr)
				}
				udpAddrs = append(udpAddrs, addr)
			}
			bconn, bErr := NewBroadcastUDPConn(udpAddrs)
			if bErr != nil {
				cancel()
				return fmt.Errorf("opening UDP socket: %v", bErr)
			}
			pconn = bconn
			remoteAddr = turbotunnel.DummyAddr{}
			log.Printf("multi-resolver UDP: %d resolvers (broadcast)", len(udpAddrs))
		}
	}

	// Wrap the transport with DNSPacketConn for DNS encoding.
	pconn = dnsttclient.NewDNSPacketConn(pconn, remoteAddr, domain)

	// For multi-resolver, normalize addresses on ReadFrom so KCP's address
	// filter doesn't drop packets. KCP compares addr.String() from ReadFrom
	// against remoteAddr.String() — responses from different resolvers would
	// have different addresses and get silently dropped.
	if remoteAddr == (turbotunnel.DummyAddr{}) {
		pconn = &AddrNormConn{PacketConn: pconn, fixedAddr: turbotunnel.DummyAddr{}}
	}

	// Resolve the local TCP listen address.
	localAddr, err := net.ResolveTCPAddr("tcp", c.listenAddr)
	if err != nil {
		pconn.Close()
		cancel()
		return fmt.Errorf("resolving listen address: %v", err)
	}

	c.running = true

	go func() {
		err := c.run(ctx, c.pubkey, domain, localAddr, remoteAddr, pconn)
		if err != nil && ctx.Err() == nil {
			log.Printf("dnstt client: %v", err)
		}
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	return nil
}

// Stop shuts down the DNSTT tunnel.
func (c *DnsttClient) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.listener != nil {
		c.listener.Close()
		c.listener = nil
	}
	c.running = false
}

// IsRunning returns whether the client is currently running.
func (c *DnsttClient) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	capacity := 255
	capacity -= 1
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * 63 / 64
	capacity = capacity * 5 / 8
	return capacity
}

// utlsDialContext connects to the given network address and initiates a TLS
// handshake with the provided ClientHelloID.
func utlsDialContext(ctx context.Context, network, addr string, config *utls.Config, id *utls.ClientHelloID) (*utls.UConn, error) {
	if config == nil {
		config = &utls.Config{}
	}
	if config.ServerName == "" {
		config = config.Clone()
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		config.ServerName = host
	}
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(conn, config, *id)
	err = uconn.Handshake()
	if err != nil {
		uconn.Close()
		return nil, err
	}
	return uconn, nil
}

// handle proxies data between a local TCP connection and a smux stream.
func handle(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

// run is the main tunnel loop: KCP → Noise → smux → TCP listener.
func (c *DnsttClient) run(ctx context.Context, pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn) error {
	defer pconn.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	c.mu.Lock()
	c.listener = ln
	c.mu.Unlock()
	defer ln.Close()

	// Close listener when context is canceled.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// Open a KCP conn on the PacketConn.
	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	defer func() {
		log.Printf("end session %08x", conn.GetConv())
		conn.Close()
	}()
	log.Printf("begin session %08x", conn.GetConv())

	// Upstream KCP defaults.
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(64, 64)
	if rc := conn.SetMtu(mtu); !rc {
		panic(rc)
	}

	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		return err
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	defer sess.Close()

	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // Shutdown requested.
			}
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			err := handle(local.(*net.TCPConn), sess, conn.GetConv())
			if err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}
