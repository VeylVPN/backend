package dns

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func buildQuery(id uint16, name string, qtype uint16, edns bool) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], flagRD)
	binary.BigEndian.PutUint16(b[4:], 1)
	if name != "" {
		for _, l := range strings.Split(name, ".") {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, classIN)
	if edns {
		binary.BigEndian.PutUint16(b[10:], 1)
		b = append(b, 0, 0, typeOPT, 0x10, 0x00, 0, 0, 0, 0, 0, 0)
	}
	return b
}

type rr struct {
	name  string
	typ   uint16
	class uint16
	ttl   uint32
	data  []byte
}

type msg struct {
	id     uint16
	flags  uint16
	qname  string
	qtype  uint16
	qclass uint16
	answer []rr
	extra  []rr
}

func (m msg) rcode() int { return int(m.flags & 0xf) }

func readName(b []byte, off int) (string, int, error) {
	var parts []string
	end := -1
	for hops := 0; hops < 32; hops++ {
		if off >= len(b) {
			return "", 0, errMalformed
		}
		n := int(b[off])
		if n == 0 {
			if end < 0 {
				end = off + 1
			}
			return strings.Join(parts, "."), end, nil
		}
		if n&0xc0 == 0xc0 {
			if off+2 > len(b) {
				return "", 0, errMalformed
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			continue
		}
		if off+1+n > len(b) {
			return "", 0, errMalformed
		}
		parts = append(parts, string(b[off+1:off+1+n]))
		off += 1 + n
	}
	return "", 0, errMalformed
}

func parseMsg(b []byte) (msg, error) {
	var m msg
	if len(b) < 12 {
		return m, errMalformed
	}
	m.id = binary.BigEndian.Uint16(b)
	m.flags = binary.BigEndian.Uint16(b[2:])
	qd := binary.BigEndian.Uint16(b[4:])
	an := int(binary.BigEndian.Uint16(b[6:]))
	ns := int(binary.BigEndian.Uint16(b[8:]))
	ar := int(binary.BigEndian.Uint16(b[10:]))
	if qd != 1 {
		return m, errors.New("qdcount")
	}
	name, off, err := readName(b, 12)
	if err != nil {
		return m, err
	}
	if off+4 > len(b) {
		return m, errMalformed
	}
	m.qname = name
	m.qtype = binary.BigEndian.Uint16(b[off:])
	m.qclass = binary.BigEndian.Uint16(b[off+2:])
	off += 4
	for i := 0; i < an+ns+ar; i++ {
		var r rr
		r.name, off, err = readName(b, off)
		if err != nil {
			return m, err
		}
		if off+10 > len(b) {
			return m, errMalformed
		}
		r.typ = binary.BigEndian.Uint16(b[off:])
		r.class = binary.BigEndian.Uint16(b[off+2:])
		r.ttl = binary.BigEndian.Uint32(b[off+4:])
		n := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if off+n > len(b) {
			return m, errMalformed
		}
		r.data = b[off : off+n]
		off += n
		switch {
		case i < an:
			m.answer = append(m.answer, r)
		case i >= an+ns:
			m.extra = append(m.extra, r)
		}
	}
	if off != len(b) {
		return m, errors.New("trailing bytes")
	}
	return m, nil
}

type fakeUpstream struct {
	t        *testing.T
	udp      *net.UDPConn
	tcp      *net.TCPListener
	addr     string
	dropUDP  atomic.Int32
	truncUDP atomic.Bool
	tcpPad   atomic.Int32
	udpHits  atomic.Int32
	tcpHits  atomic.Int32
	wg       sync.WaitGroup
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u, l, err := listenPair("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUpstream{t: t, udp: u, tcp: l, addr: u.LocalAddr().String()}
	f.wg.Add(2)
	go f.serveUDP()
	go f.serveTCP()
	t.Cleanup(func() {
		u.Close()
		l.Close()
		f.wg.Wait()
	})
	return f
}

func (f *fakeUpstream) answer(q []byte, trunc bool, pad int) []byte {
	pq, err := ParseQuery(q)
	if err != nil {
		return nil
	}
	out := make([]byte, 12)
	copy(out, q[:2])
	flags := uint16(flagQR | flagRA | flagRD)
	if trunc {
		flags |= flagTC
	}
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[4:], 1)
	out = append(out, q[12:pq.End]...)
	if trunc {
		return out
	}
	n := 1 + pad
	binary.BigEndian.PutUint16(out[6:], uint16(n))
	for i := 0; i < n; i++ {
		out = append(out, 0xc0, 12, 0, typeA, 0, classIN, 0, 0, 0, 60, 0, 4, 192, 0, 2, byte(i+1))
	}
	return out
}

func (f *fakeUpstream) serveUDP() {
	defer f.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, src, err := f.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		f.udpHits.Add(1)
		if f.dropUDP.Load() > 0 {
			f.dropUDP.Add(-1)
			continue
		}
		if resp := f.answer(buf[:n], f.truncUDP.Load(), 0); resp != nil {
			f.udp.WriteToUDPAddrPort(resp, src)
		}
	}
}

func (f *fakeUpstream) serveTCP() {
	defer f.wg.Done()
	for {
		c, err := f.tcp.Accept()
		if err != nil {
			return
		}
		f.tcpHits.Add(1)
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			var lb [2]byte
			if _, err := io.ReadFull(c, lb[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(lb[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			resp := f.answer(q, false, int(f.tcpPad.Load()))
			out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
			c.Write(append(out, resp...))
		}()
	}
}

func udpExchange(t *testing.T, addr string, q []byte, wait time.Duration) ([]byte, error) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(wait))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func tcpExchange(t *testing.T, addr string, qs ...[]byte) [][]byte {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var out [][]byte
	for _, q := range qs {
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
			t.Fatal(err)
		}
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			t.Fatal(err)
		}
		r := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}
