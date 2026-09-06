//go:build !windows

package discover

import (
	"context"
	"net"
	"os"
	"syscall"
	"time"
)

// probe is the sweep itself, reporting how many probes it could not even send.
//
// The count matters to whoever asked: a host that was never pinged has not been found
// absent, it has not been looked for. Treating the two the same is how a loaded machine
// that could not get its packets onto the wire ends up reporting a network as gone.
func probe(ctx context.Context, hosts []net.IP, timeout time.Duration) ([]net.IP, int, error) {
	if timeout <= 0 {
		return nil, len(hosts), context.DeadlineExceeded
	}
	if len(hosts) == 0 {
		return nil, 0, nil
	}

	connection, err := openICMP()
	if err != nil {
		return nil, 0, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()

	return probeWithConnection(connection, hosts, timeout)
}

// openICMP prefers the unprivileged datagram socket, which macOS and most Linux
// distributions allow any user to open, and falls back to a raw one where it does not.
// Only when neither is permitted is the sweep genuinely impossible.
func openICMP() (net.PacketConn, error) {
	if connection, err := datagramICMP(); err == nil {
		return connection, nil
	}

	connection, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, ErrNoProbe
	}

	return connection, nil
}

// datagramICMP opens an unprivileged ICMP socket, the one modern ping uses.
func datagramICMP() (net.PacketConn, error) {
	descriptor, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, protocolICMP)
	if err != nil {
		return nil, err
	}

	if err := syscall.SetNonblock(descriptor, true); err != nil {
		_ = syscall.Close(descriptor)

		return nil, err
	}

	file := os.NewFile(uintptr(descriptor), "icmp")
	defer file.Close()

	return net.FilePacketConn(file)
}
