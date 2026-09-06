package discover

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

type probeSocket struct {
	local        net.Addr
	destinations []net.Addr
	sendError    error
}

func (s *probeSocket) LocalAddr() net.Addr              { return s.local }
func (s *probeSocket) Close() error                     { return nil }
func (s *probeSocket) SetDeadline(time.Time) error      { return nil }
func (s *probeSocket) SetReadDeadline(time.Time) error  { return nil }
func (s *probeSocket) SetWriteDeadline(time.Time) error { return nil }
func (s *probeSocket) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, &net.OpError{Op: "read", Err: timeoutError{}}
}
func (s *probeSocket) WriteTo(_ []byte, destination net.Addr) (int, error) {
	s.destinations = append(s.destinations, destination)
	return 0, s.sendError
}

func TestProbeSupportsRawAndDatagramSockets(t *testing.T) {
	host := net.ParseIP("192.168.1.10")
	for _, raw := range []bool{true, false} {
		socket := &probeSocket{local: &net.UDPAddr{}}
		if raw {
			socket.local = &net.IPAddr{}
		}
		_, undelivered, err := probeWithConnection(socket, []net.IP{host}, time.Millisecond)
		if err != nil || undelivered != 0 || len(socket.destinations) != 1 {
			t.Fatalf("probe failed: %v, unsent=%d", err, undelivered)
		}
		switch address := socket.destinations[0].(type) {
		case *net.IPAddr:
			if !raw || !address.IP.Equal(host) {
				t.Fatal("wrong raw destination")
			}
		case *net.UDPAddr:
			if raw || !address.IP.Equal(host) {
				t.Fatal("raw socket received a UDP destination")
			}
		default:
			t.Fatalf("unexpected destination %T", address)
		}
	}
}

func TestProbeCountsUnsentPackets(t *testing.T) {
	socket := &probeSocket{local: &net.IPAddr{}, sendError: errors.New("send buffer full")}
	replies, undelivered, err := probeWithConnection(socket, []net.IP{net.ParseIP("192.168.1.10")}, time.Millisecond)
	if err != nil || undelivered != 1 || len(replies) != 0 {
		t.Fatalf("lost send failure: replies=%v, unsent=%d, error=%v", replies, undelivered, err)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// The kernel caches a failed ARP resolution, so the first sweep of a subnet sees an
// absent host go silent and every sweep after it sees the send itself refused. Both are
// the same absent device. Counting the second as a send failure is how a device stops
// being reported offline at all, and how a subnet stops being claimed as covered — so
// the server stops ageing out the devices that left it.
func TestUnreachableHostIsAbsenceRatherThanAFailedSend(t *testing.T) {
	for _, refusal := range []syscall.Errno{
		syscall.EHOSTUNREACH,
		syscall.EHOSTDOWN,
		syscall.ENETUNREACH,
		syscall.ENETDOWN,
	} {
		socket := &probeSocket{
			local:     &net.UDPAddr{},
			sendError: &net.OpError{Op: "write", Err: refusal},
		}

		replies, undelivered, err := probeWithConnection(socket, []net.IP{net.ParseIP("192.168.1.10")}, time.Millisecond)

		if err != nil {
			t.Fatalf("%v: %v", refusal, err)
		}

		if undelivered != 0 {
			t.Fatalf("%v was counted as a probe that never left the host", refusal)
		}

		if len(replies) != 0 {
			t.Fatalf("%v: an unreachable host must not read as present", refusal)
		}
	}
}

// Anything else really is a packet that never left, and must not be read as absence:
// a host nobody asked has not been found missing.
func TestOtherSendFailuresAreStillCounted(t *testing.T) {
	for _, failure := range []error{
		&net.OpError{Op: "write", Err: syscall.ENOBUFS},
		&net.OpError{Op: "write", Err: syscall.EACCES},
		&net.OpError{Op: "write", Err: syscall.EPERM},
		errors.New("send buffer full"),
	} {
		socket := &probeSocket{local: &net.UDPAddr{}, sendError: failure}

		_, undelivered, err := probeWithConnection(socket, []net.IP{net.ParseIP("192.168.1.10")}, time.Millisecond)
		if err != nil || undelivered != 1 {
			t.Fatalf("%v was swallowed: unsent=%d, error=%v", failure, undelivered, err)
		}
	}
}
