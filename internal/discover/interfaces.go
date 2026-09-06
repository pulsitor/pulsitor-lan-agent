// Package discover finds the hosts on the networks the agent is attached to.
package discover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Attached is one usable IPv4 network the machine sits on.
type Attached struct {
	Name string
	CIDR string
	Net  *net.IPNet
}

// maxHosts caps how wide a network the agent will sweep. Anything larger is either a
// misconfiguration or somebody pointing the agent at a network it has no business
// walking, and either way the sweep would take longer than the interval.
const maxHosts = 1024

// Attachments lists the private IPv4 networks worth sweeping. Loopback, down links and
// anything routable on the public internet are left out: the agent exists to see inside
// one LAN, not to scan the world from inside a customer's office.
func Attachments() ([]Attached, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	found := []Attached{}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, address := range addresses {
			network, ok := address.(*net.IPNet)
			if !ok || network.IP.To4() == nil || !IsPrivate(network.IP) {
				continue
			}

			ones, bits := network.Mask.Size()
			if bits-ones > 10 || 1<<(bits-ones) > maxHosts {
				continue
			}

			found = append(found, Attached{
				Name: iface.Name,
				CIDR: (&net.IPNet{IP: network.IP.Mask(network.Mask), Mask: network.Mask}).String(),
				Net:  network,
			})
		}
	}

	return found, nil
}

// Hosts enumerates every address in a network except the network and broadcast ones.
func Hosts(network *net.IPNet) ([]net.IP, error) {
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 networks can be swept")
	}
	if 1<<(bits-ones) > maxHosts {
		return nil, fmt.Errorf("%s is wider than the %d host limit", network.String(), maxHosts)
	}

	base := network.IP.Mask(network.Mask).To4()
	if base == nil {
		return nil, fmt.Errorf("%s is not an IPv4 network", network.String())
	}

	total := uint32(1) << uint(bits-ones)
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])

	hosts := make([]net.IP, 0, total)

	for offset := uint32(0); offset < total; offset++ {
		// A /31 or /32 has no network or broadcast address to skip.
		if total > 2 && (offset == 0 || offset == total-1) {
			continue
		}

		value := start + offset
		hosts = append(hosts, net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)))
	}

	return hosts, nil
}

// privateRanges mirrors the server's idea of an address an agent may report.
var privateRanges = func() []*net.IPNet {
	ranges := []*net.IPNet{}

	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	} {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			ranges = append(ranges, network)
		}
	}

	return ranges
}()

// IsPrivate reports whether an address belongs to a network an agent may sweep.
func IsPrivate(ip net.IP) bool {
	for _, network := range privateRanges {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// ErrOffLAN says some requested addresses are not on any network this machine is
// attached to, so they were never put on the wire.
//
// Deliberately its own error rather than a plain failure. A target can sit outside every
// attached network for a long time — a device whose subnet the agent left, whose last
// known address the server keeps handing back because the agent has not managed to say
// anything about it. Read as a probe failure, that one stale device would take the whole
// round down the cautious path and stop every *other* device on the agent from ever
// being reported offline, for as long as it stayed stale. The caller is told separately
// so it can keep reporting the targets it could actually reach.
var ErrOffLAN = errors.New("some targets are outside the attached LAN networks")

// ProbeLocal enforces local attachment for monitored addresses as well as discovery.
func ProbeLocal(hosts []net.IP, timeout time.Duration) ([]net.IP, error) {
	return ProbeLocalContext(context.Background(), hosts, timeout)
}

func ProbeLocalContext(ctx context.Context, hosts []net.IP, timeout time.Duration) ([]net.IP, error) {
	attachments, err := Attachments()
	if err != nil {
		return nil, err
	}
	var allowed []net.IP
	rejected := false
	for _, ip := range hosts {
		ok := false
		for _, attachment := range attachments {
			if attachment.Net.Contains(ip) && !isEdgeAddress(ip, attachment.Net) {
				ok = true
				break
			}
		}
		if ok {
			allowed = append(allowed, ip)
		} else {
			rejected = true
		}
	}
	found, err := ProbeContext(ctx, allowed, timeout)

	// Only when the probe itself was fine: a real send failure is the more serious of
	// the two and must not be masked by this one.
	if err == nil && rejected {
		err = ErrOffLAN
	}

	return found, err
}
