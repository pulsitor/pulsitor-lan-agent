package discover

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// icmpEchoRequest is the ICMP type for an echo, and icmpEchoReply what a live host sends back.
const (
	icmpEchoRequest = 8
	icmpEchoReply   = 0
)

// protocolICMP is IPPROTO_ICMP, for the datagram socket below.
const protocolICMP = 1

// replySettleWindow is how long the sweep keeps listening after the last probe went
// out. A host on the same segment answers in well under a millisecond; anything that
// has not replied by now is not going to.
const replySettleWindow = 2 * time.Second

// ErrNoProbe says this process may open neither an unprivileged nor a raw ICMP socket,
// so nothing can be actively probed. Presence then has to fall back to the operating
// system's neighbour table, which cannot tell a device that is here from one that left
// a few minutes ago.
var ErrNoProbe = errors.New("no ICMP socket available")

// Sweep pings every host in a network and returns the addresses that answered.
//
// This is what establishes presence. The neighbour table cannot: an ARP entry outlives
// the device by many minutes, so a departed host keeps looking connected. Only an answer
// to a probe sent now proves anything.
func Sweep(network *net.IPNet, timeout time.Duration) ([]net.IP, int, error) {
	hosts, err := Hosts(network)
	if err != nil {
		return nil, 0, err
	}

	return probe(context.Background(), hosts, timeout)
}

// Probe pings a named set of hosts and returns those that answered.
//
// This is the monitoring path: a handful of addresses the server asked about, rather
// than a whole subnet. Every host due in the same round goes out on one socket and
// shares one settle window, so watching twenty devices costs the same wait as watching
// one.
func Probe(hosts []net.IP, timeout time.Duration) ([]net.IP, error) {
	return ProbeContext(context.Background(), hosts, timeout)
}

func ProbeContext(ctx context.Context, hosts []net.IP, timeout time.Duration) ([]net.IP, error) {
	answered, undelivered, err := probe(ctx, hosts, timeout)
	if err == nil && undelivered > 0 {
		err = fmt.Errorf("%d ICMP probe(s) could not be sent", undelivered)
	}

	return answered, err
}

func probeWithConnection(connection net.PacketConn, hosts []net.IP, timeout time.Duration) ([]net.IP, int, error) {
	var (
		waiting  sync.WaitGroup
		guard    sync.Mutex
		answered = make(map[string]struct{}, len(hosts))
	)

	// The timeout is the ceiling, not the plan: it bounds a sweep that hangs. The
	// deadline is shortened to a short quiet window once the probes are all out,
	// because a LAN round trip is sub-millisecond and holding the socket open for the
	// full ceiling would spend the whole reporting interval waiting for nobody.
	if timeout <= 0 {
		return nil, len(hosts), context.DeadlineExceeded
	}
	deadline := time.Now().Add(timeout)
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, len(hosts), err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, len(hosts), err
	}
	expected := make(map[string]map[uint16]bool, len(hosts))
	for i, host := range hosts {
		if expected[host.String()] == nil {
			expected[host.String()] = map[uint16]bool{}
		}
		expected[host.String()][uint16(i)] = true
	}
	var readError error

	waiting.Add(1)

	go func() {
		defer waiting.Done()

		buffer := make([]byte, 1500)

		for {
			read, from, err := connection.ReadFrom(buffer)
			if err != nil {
				if timeoutErr, ok := err.(net.Error); !ok || !timeoutErr.Timeout() {
					readError = err
				}
				return
			}
			packet := echoPayload(buffer[:read])
			if !isEchoReply(packet) || len(packet) != 24 || !bytes.Equal(packet[8:], nonce) || !expected[addressOf(from)][binary.BigEndian.Uint16(packet[6:8])] {
				continue
			}

			guard.Lock()
			answered[addressOf(from)] = struct{}{}
			guard.Unlock()
		}
	}()

	undelivered := 0

	for index, host := range hosts {
		if time.Now().After(deadline) {
			undelivered += len(hosts) - index
			break
		}
		packet := append(echoRequest(uint16(index&0xFFFF)), nonce...)
		packet[2], packet[3] = 0, 0
		binary.BigEndian.PutUint16(packet[2:4], checksum(packet))
		if _, err := connection.WriteTo(packet, probeAddress(connection, host)); err != nil && !isAbsence(err) {
			// A send that failed for any other reason — usually a full buffer — means
			// the host was never asked, so its silence says nothing about it.
			undelivered++
		}

		// Sending a whole /24 as fast as the socket accepts it makes switches drop
		// replies, so the sweep is paced rather than blasted.
		time.Sleep(time.Millisecond)
	}

	if settle := time.Now().Add(replySettleWindow); settle.Before(deadline) {
		_ = connection.SetReadDeadline(settle)
	}

	waiting.Wait()

	found := make([]net.IP, 0, len(answered))
	for address := range answered {
		if ip := net.ParseIP(address); ip != nil {
			found = append(found, ip)
		}
	}

	return found, undelivered, readError
}

// isAbsence reports whether a write error is the kernel telling us nobody is at that
// address, rather than the packet failing to leave this machine.
//
// This distinction decides whether a device is reported offline or not reported at all,
// and getting it wrong is invisible until the second sweep. On a link-local destination
// the kernel resolves the address by ARP before it can send; when nothing answers, it
// caches that failure and every later send returns EHOSTUNREACH immediately. So the
// first sweep of a subnet sees a silent host and the ones after it see a failed send —
// the same absent device, reported two different ways.
//
// Counted as a send failure, that is a device that stops being reported offline at all
// once its neighbour entry goes bad, and a whole subnet that is never claimed as
// covered, so the server stops ageing out devices that left. Counted as absence, which
// is what it is, both keep working. Windows already draws this line: IcmpSendEcho's
// destination-unreachable statuses are read as absence there.
func isAbsence(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EHOSTDOWN) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.ENETDOWN)
}

// Raw sockets use IP addresses; ping datagram sockets use UDP addresses.
func probeAddress(connection net.PacketConn, host net.IP) net.Addr {
	if _, raw := connection.LocalAddr().(*net.IPAddr); raw {
		return &net.IPAddr{IP: host}
	}
	return &net.UDPAddr{IP: host}
}

// addressOf strips the port a datagram socket reports alongside the address.
func addressOf(from net.Addr) string {
	if udp, ok := from.(*net.UDPAddr); ok {
		return udp.IP.String()
	}

	return from.String()
}

// echoRequest builds an ICMP echo with its checksum filled in.
//
// The identifier is left to the kernel: an unprivileged datagram socket rewrites it, so
// a reply is matched by the address it came from rather than by anything we put in it.
func echoRequest(sequence uint16) []byte {
	packet := make([]byte, 8)
	packet[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(packet[6:8], sequence)
	binary.BigEndian.PutUint16(packet[2:4], checksum(packet))

	return packet
}

// isEchoReply reports whether a datagram is an echo reply.
func echoPayload(packet []byte) []byte {
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		n := int(packet[0]&0x0F) * 4
		if n < 20 || n > len(packet) || packet[9] != protocolICMP {
			return nil
		}
		return packet[n:]
	}
	return packet
}

func isEchoReply(packet []byte) bool {
	packet = echoPayload(packet)
	return len(packet) >= 8 && packet[0] == icmpEchoReply && packet[1] == 0
}

// checksum is the ones-complement sum the ICMP header carries.
func checksum(data []byte) uint16 {
	var sum uint32

	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(data[index])<<8 | uint32(data[index+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum>>16 > 0 {
		sum = sum&0xFFFF + sum>>16
	}

	return ^uint16(sum)
}

func SweepContext(ctx context.Context, network *net.IPNet, timeout time.Duration) ([]net.IP, int, error) {
	hosts, err := Hosts(network)
	if err != nil {
		return nil, 0, err
	}
	return probe(ctx, hosts, timeout)
}
