//go:build linux

package tcpraw

import (
	"container/list"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	errTimeout = errors.New("timeout") // Error for operation timeout
	expire     = time.Minute           // Duration to define expiration time for flows
	connList   list.List
	connListMu sync.Mutex
)

const messageBufferSize = 65536 // Adjust based on needs

var globalOpts = &gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// a message from NIC
type message struct {
	bts  []byte
	addr net.Addr
}

// TCPConn, a wrapper for tcpconn for gc purpose
type TCPConn struct {
	*tcpConn
}

type flowKey struct {
	ip   [16]byte // IPv6 max size
	port int
}

// a tcp flow information of a connection pair
type tcpFlow struct {
	conn       *net.TCPConn             // the related system TCP connection of this flow
	handle     *net.IPConn              // the handle to send packets
	seq        atomic.Uint32            // TCP sequence number
	ack        atomic.Uint32            // TCP acknowledge number
	ts         time.Time                // last packet incoming time
	buf        gopacket.SerializeBuffer // a buffer for write
	tcpHeader  layers.TCP
	mu         sync.Mutex // mutex for ack, ts,seq and handle...
	ipv4Header layers.IPv4
	ipv6Header layers.IPv6
	lport      int
}

// tcpConn defines a TCP-packet oriented connection
type tcpConn struct {
	elem    *list.Element // elem in the list
	die     chan struct{}
	dieOnce sync.Once

	// the main golang sockets
	dialerConn *net.TCPConn     // from net.Dial
	listener   *net.TCPListener // from net.Listen

	// handles
	handles []*net.IPConn

	// packets captured from all related NICs will be delivered to this channel
	chMessage chan message

	// all TCP flows
	flowTable map[flowKey]*tcpFlow
	flowMu    sync.RWMutex

	// iptables
	iptables  *iptables.IPTables // Handle for IPv4 iptables rules
	iprule    []string           // IPv4 iptables rule associated with the connection
	ip6tables *iptables.IPTables // Handle for IPv6 iptables rules
	ip6rule   []string           // IPv6 iptables rule associated with the connection

	// deadlines
	readDeadline  atomic.Value // Atomic value for read deadline
	writeDeadline atomic.Value // Atomic value for write deadline

	readBuf []byte // simple leftover buffer
}

func makeFlowKey(addr net.Addr) flowKey {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		panic("makeFlowKey: expected *net.TCPAddr")
	}

	var key flowKey
	ip := tcpAddr.IP.To16()
	if ip == nil {
		panic("makeFlowKey: invalid IP")
	}
	copy(key.ip[:], ip)
	key.port = tcpAddr.Port
	return key
}

func (conn *tcpConn) getOrCreateFlow(addr net.Addr) *tcpFlow {
	key := makeFlowKey(addr)

	conn.flowMu.RLock()
	flow, exists := conn.flowTable[key]
	conn.flowMu.RUnlock()

	if !exists {
		flow = &tcpFlow{
			ts:         getLocalTime(),
			buf:        gopacket.NewSerializeBuffer(),
			ipv4Header: layers.IPv4{Protocol: layers.IPProtocolTCP},
			ipv6Header: layers.IPv6{NextHeader: layers.IPProtocolTCP},
		}
		conn.flowMu.Lock()
		conn.flowTable[key] = flow
		conn.flowMu.Unlock()
	}
	return flow
}

// Dial connects to the remote TCP port and returns a single packet-oriented connection
func Dial(network, address string) (*TCPConn, error) {
	// remote address resolve
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// AF_INET
	handle, err := net.DialIP("ip:tcp", nil, &net.IPAddr{IP: raddr.IP})
	if err != nil {
		return nil, err
	}

	// create an established tcp connection, will hack this tcp connection for packet transmission
	tcpconn, err := net.DialTCP(network, nil, raddr)
	if err != nil {
		return nil, err
	}

	// parse local ip and port from tcpconn
	laddr, lport, err := net.SplitHostPort(tcpconn.LocalAddr().String())
	if err != nil {
		return nil, err
	}

	// fields
	conn := new(tcpConn)
	conn.die = make(chan struct{})
	conn.flowTable = make(map[flowKey]*tcpFlow)
	conn.dialerConn = tcpconn
	conn.chMessage = make(chan message, messageBufferSize) // buffer up to 10k message!
	flow := conn.getOrCreateFlow(tcpconn.RemoteAddr())
	flow.conn = tcpconn
	flow.lport = tcpconn.LocalAddr().(*net.TCPAddr).Port
	conn.handles = append(conn.handles, handle)

	go conn.captureFlow(handle, tcpconn.LocalAddr().(*net.TCPAddr).Port)
	go conn.cleaner()

	// iptables
	err = setTTL(tcpconn, 1)
	if err != nil {
		return nil, err
	}

	// setup iptables only when it's the first connection
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4); err == nil {
		rule := []string{"-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "-s", laddr, "--sport", lport, "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.iprule = rule
					conn.iptables = ipt
				}
			}
		}
	}
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		rule := []string{"-m", "hl", "--hl-eq", "1", "-p", "tcp", "-s", laddr, "--sport", lport, "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.ip6rule = rule
					conn.ip6tables = ipt
				}
			}
		}
	}

	// discard everything
	go io.Copy(io.Discard, tcpconn)

	// push back to the global list and set the elem
	connListMu.Lock()
	conn.elem = connList.PushBack(conn)
	connListMu.Unlock()

	return wrapConn(conn), nil
}

// Listen acts like net.ListenTCP and returns a single packet-oriented connection
func Listen(network, address string) (*TCPConn, error) {
	// fields
	conn := new(tcpConn)
	conn.flowTable = make(map[flowKey]*tcpFlow)
	conn.die = make(chan struct{})
	conn.chMessage = make(chan message, messageBufferSize)

	// resolve address
	laddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// AF_INET
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	if laddr.IP == nil || laddr.IP.IsUnspecified() { // if address is not specified, capture on all ifaces
		var lasterr error
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipaddr, ok := addr.(*net.IPNet); ok {
						if handle, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: ipaddr.IP}); err == nil {
							conn.handles = append(conn.handles, handle)
							go conn.captureFlow(handle, laddr.Port)
						} else {
							lasterr = err
						}
					}
				}
			}
		}

		if len(conn.handles) == 0 {
			return nil, lasterr
		}

	} else {
		if handle, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: laddr.IP}); err == nil {
			conn.handles = append(conn.handles, handle)
			go conn.captureFlow(handle, laddr.Port)

		} else {
			return nil, err
		}
	}

	// start listening
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	conn.listener = l

	// start cleaner
	go conn.cleaner()

	// iptables drop packets marked with TTL = 1
	// TODO: what if iptables is not available, the next hop will send back ICMP Time Exceeded,
	// is this still an acceptable behavior?
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4); err == nil {
		rule := []string{"-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.iprule = rule
					conn.iptables = ipt
				}
			}
		}
	}

	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		rule := []string{"-m", "hl", "--hl-eq", "1", "-p", "tcp", "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.ip6rule = rule
					conn.ip6tables = ipt
				}
			}
		}
	}

	// discard everything in original connection
	go func() {
		for {
			tcpconn, err := l.AcceptTCP()
			if err != nil {
				return
			}

			// if we cannot set TTL = 1, the only thing reasonable is panic
			if err := setTTL(tcpconn, 1); err != nil {
				panic(err)
			}

			// record net.Conn
			flow := conn.getOrCreateFlow(tcpconn.RemoteAddr())
			flow.conn = tcpconn
			flow.lport = conn.listener.Addr().(*net.TCPAddr).Port

			// discard everything
			go io.Copy(io.Discard, tcpconn)
		}
	}()

	// push back to the global list and set the elem
	connListMu.Lock()
	conn.elem = connList.PushBack(conn)
	connListMu.Unlock()

	return wrapConn(conn), nil
}

// Create a sync.Pool for buffer reuse
var bufPool = &sync.Pool{
	New: func() interface{} {
		// Initialize a buffer of a reasonable size (e.g., 2048 bytes)
		buf := make([]byte, 2048)
		return &buf // Return a pointer to the byte slice
	},
}

// captureFlow capture every inbound packets based on rules of BPF
func (conn *tcpConn) captureFlow(handle *net.IPConn, port int) {
	buf := bufPool.Get().(*[]byte) // Get a pointer to the buffer
	defer bufPool.Put(buf)         // Return the pointer to the pool when done

	opt := gopacket.DecodeOptions{NoCopy: true, Lazy: true}

	for {
		n, addr, err := handle.ReadFromIP(*buf)
		if err != nil {
			return
		}
	 
		packet := gopacket.NewPacket((*buf)[:n], layers.LayerTypeTCP, opt)
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok || int(tcp.DstPort) != port {
			continue
		}

		src := &net.TCPAddr{IP: addr.IP, Port: int(tcp.SrcPort)}

		// flow maintaince
		flow := conn.getOrCreateFlow(src)

		// Update flow metadata
		flow.ts = getLocalTime()

		if tcp.ACK {
			flow.seq.Store(tcp.Ack)
		}
		if tcp.SYN {
			flow.ack.Store(tcp.Seq + 1)
		}
		if tcp.PSH && flow.ack.Load() == tcp.Seq {
			flow.ack.Store(tcp.Seq + uint32(len(tcp.Payload)))
		}

		if flow.handle == nil {
			flow.handle = handle
		}

		if flow.conn == nil {
			continue
		}

		// deliver packet
		if tcp.PSH {
			payload := make([]byte, len(tcp.Payload))
			copy(payload, tcp.Payload)
			select {
			case conn.chMessage <- message{bts: payload, addr: src}:
			case <-conn.die:
				return
			}
		}
	}
}

// clean expired flows
func (conn *tcpConn) cleaner() {
	ticker := time.NewTicker(time.Minute) // Create a ticker to trigger flow cleanup every minute
	defer ticker.Stop()

	for {
		select {
		case <-conn.die: // Exit if the connection is closed
			return
		case <-ticker.C: // On each tick, clean up expired flows
			conn.flowMu.Lock()
			for k, v := range conn.flowTable {
				if time.Since(v.ts) > expire { // Check if the flow has expired
					if v.conn != nil {
						setTTL(v.conn, 64) // Set TTL before closing the connection
						v.conn.Close()
					}
					delete(conn.flowTable, k) // Remove the flow from the table
				}
			}
			conn.flowMu.Unlock()
		}
	}
}

func (conn *tcpConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var deadline <-chan time.Time
	if d, ok := conn.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	// Serve from leftover buffer first
	if len(conn.readBuf) > 0 {
		n := copy(p, conn.readBuf)
		conn.readBuf = conn.readBuf[n:]
		return n, nil, nil
	}

	select {
	case <-deadline:
		return 0, nil, errTimeout
	case <-conn.die:
		return 0, nil, io.EOF
	case pkt := <-conn.chMessage:
		// Copy as much as we can
		n := copy(p, pkt.bts)
		if n < len(pkt.bts) {
			// Save remaining bytes
			conn.readBuf = pkt.bts[n:]
		}
		return n, pkt.addr, nil
	}
}

// WriteTo implements the PacketConn WriteTo method.
func (conn *tcpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var deadline <-chan time.Time
	if d, ok := conn.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		deadline = timer.C
		defer timer.Stop()
	}

	select {
	case <-deadline:
		return 0, errTimeout
	case <-conn.die:
		return 0, io.EOF
	default:
		flow := conn.getOrCreateFlow(addr)

		// if the flow doesn't have handle , assume this packet has lost, without notification
		if flow.handle == nil {
			// treat as send silently
			return len(p), nil
		}

		flow.tcpHeader.Ack = flow.ack.Load()
		flow.tcpHeader.Seq = flow.seq.Load()

		flow.mu.Lock()

		// build tcp header with local and remote port
		flow.tcpHeader.SrcPort = layers.TCPPort(flow.lport)
		flow.tcpHeader.DstPort = layers.TCPPort(addr.(*net.TCPAddr).Port)
		flow.tcpHeader.Window = linuxFingerPrint.Window
		flow.tcpHeader.PSH = true
		flow.tcpHeader.ACK = true
		flow.tcpHeader.Options = linuxFingerPrint.Options

		setTimestampOption(flow.tcpHeader.Options)

		if addr.(*net.TCPAddr).IP.To4() != nil {
			flow.ipv4Header.SrcIP = flow.handle.LocalAddr().(*net.IPAddr).IP.To4()
			flow.ipv4Header.DstIP = addr.(*net.TCPAddr).IP.To4()
			flow.tcpHeader.SetNetworkLayerForChecksum(&flow.ipv4Header)
		} else {
			flow.ipv6Header.SrcIP = flow.handle.LocalAddr().(*net.IPAddr).IP.To16()
			flow.ipv6Header.DstIP = addr.(*net.TCPAddr).IP.To16()
			flow.tcpHeader.SetNetworkLayerForChecksum(&flow.ipv6Header)
		}

		//	flow.buf.Clear()
		gopacket.SerializeLayers(flow.buf, *globalOpts, &flow.tcpHeader, gopacket.Payload(p))

		if conn.dialerConn != nil {
			_, err = flow.handle.Write(flow.buf.Bytes())
		} else {
			_, err = flow.handle.WriteToIP(flow.buf.Bytes(), &net.IPAddr{IP: addr.(*net.TCPAddr).IP})
		}

		flow.mu.Unlock()

		// increase seq in flow
		flow.seq.Add(uint32(len(p)))

		return len(p), err
	}
}

// LocalAddr returns the local network address.
func (conn *tcpConn) LocalAddr() net.Addr {
	if conn.dialerConn != nil {
		return conn.dialerConn.LocalAddr()
	} else if conn.listener != nil {
		return conn.listener.Addr()
	}
	return nil
}

// SetDeadline implements the Conn SetDeadline method.
func (conn *tcpConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (conn *tcpConn) SetReadDeadline(t time.Time) error {
	conn.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (conn *tcpConn) SetWriteDeadline(t time.Time) error {
	conn.writeDeadline.Store(t)
	return nil
}

// SetReadBuffer sets the size of the operating system's receive buffer associated with the connection.
func (conn *tcpConn) SetReadBuffer(bytes int) error {
	var err error
	for k := range conn.handles {
		if err := conn.handles[k].SetReadBuffer(bytes); err != nil {
			return err
		}
	}
	return err
}

// SetWriteBuffer sets the size of the operating system's transmit buffer associated with the connection.
func (conn *tcpConn) SetWriteBuffer(bytes int) error {
	var err error
	for k := range conn.handles {
		if err := conn.handles[k].SetWriteBuffer(bytes); err != nil {
			return err
		}
	}
	return err
}

// Close closes the connection.
func (conn *tcpConn) Close() error {
	var err error

	conn.dieOnce.Do(func() {
		// signal closing
		close(conn.die)

		// close all established tcp connections
		if conn.dialerConn != nil { // client
			setTTL(conn.dialerConn, 64)
			err = conn.dialerConn.Close()
		} else if conn.listener != nil {
			err = conn.listener.Close() // server
			conn.flowMu.Lock()
			for k, v := range conn.flowTable {
				if v.conn != nil {
					setTTL(v.conn, 64)
					v.conn.Close()
				}
				delete(conn.flowTable, k)
			}
			conn.flowMu.Unlock()
		}

		// close handles
		for k := range conn.handles {
			conn.handles[k].Close()
		}

		// delete iptable
		if conn.iptables != nil {
			conn.iptables.Delete("filter", "OUTPUT", conn.iprule...)
		}
		if conn.ip6tables != nil {
			conn.ip6tables.Delete("filter", "OUTPUT", conn.ip6rule...)
		}

		// remove from the global list
		connListMu.Lock()
		connList.Remove(conn.elem)
		connListMu.Unlock()
	})
	return err
}

// setTTL sets the Time-To-Live field on a given connection
func setTTL(c *net.TCPConn, ttl int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.TCPAddr)

	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		})
	} else {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
	}
	return err
}

// setDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
func setDSCP(c *net.IPConn, dscp int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.IPAddr)

	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, dscp)
		})
	} else {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, dscp<<2)
		})
	}
	return err
}

// SetDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
func (conn *tcpConn) SetDSCP(dscp int) error {
	for k := range conn.handles {
		if err := setDSCP(conn.handles[k], dscp); err != nil {
			return err
		}
	}
	return nil
}

// wrapConn wraps a tcpConn in a TCPConn.
func wrapConn(conn *tcpConn) *TCPConn {
	// Set up a finalizer to ensure resources are cleaned up when the TCPConn is garbage collected
	wrapper := &TCPConn{tcpConn: conn}
	runtime.SetFinalizer(wrapper, func(wrapper *TCPConn) {
		wrapper.Close()
	})

	return wrapper
}

func IPTablesReset() {
	// gracefully shutdown all connection
	connListMu.Lock()
	var wg sync.WaitGroup
	wg.Add(connList.Len())
	for elem := connList.Front(); elem != nil; elem = elem.Next() {
		go func(conn *tcpConn) {
			conn.Close()
			wg.Done()
		}(elem.Value.(*tcpConn))
	}
	connListMu.Unlock()
	wg.Wait()
}
