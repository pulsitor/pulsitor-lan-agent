package discover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"
)

// Device is one host discovery saw. The wire shape lives in the report package; this
// is what the network layer observed, with no protocol attached to it.
type Device struct {
	MAC      string
	IP       string
	Hostname string
}

// Interface is a network the agent found itself attached to.
type Interface struct {
	Name string
	CIDR string
}

// Result is one complete observation of the networks the agent watches.
type Result struct {
	Interfaces []Interface
	Devices    []Device

	// Scanned lists the networks this sweep genuinely covered, end to end.
	//
	// A network whose sweep failed, or whose probes could not all be put on the wire,
	// is left out. Absence from Devices then means "not seen" only for the networks
	// named here; anywhere else it means "not looked at", and the server must not read
	// the two the same way and declare a whole subnet gone.
	Scanned []string

	// Degraded says nothing could be actively probed, so presence was taken from the
	// neighbour table. Worth surfacing loudly: those entries outlive the devices they
	// describe, so a departed host still reads as connected.
	Degraded bool

	// Failures are per-subnet sweep errors. They do not stop the report — what was
	// seen is still worth sending — but they must not vanish either.
	Failures []error
}

// Run sweeps every attached network the server has enabled and folds the answers
// together with the operating system's neighbour table.
func Run(enabled []string, timeout time.Duration) (Result, error) {
	return RunContext(context.Background(), enabled, timeout)
}

func RunContext(ctx context.Context, enabled []string, timeout time.Duration) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline := time.Now().Add(timeout)
	attachments, err := Attachments()
	if err != nil {
		return Result{}, err
	}

	result := Result{
		Interfaces: make([]Interface, 0, len(attachments)),
		Devices:    []Device{},
		Scanned:    []string{},
	}

	allowed := map[string]bool{}
	for _, cidr := range enabled {
		allowed[cidr] = true
	}

	seen := map[string]*Device{}

	for _, attachment := range attachments {
		result.Interfaces = append(result.Interfaces, Interface{
			Name: attachment.Name,
			CIDR: attachment.CIDR,
		})

		// The agent reports every network it is attached to, but only sweeps the ones
		// the user turned on. A subnet the server never enabled is never touched.
		if !allowed[attachment.CIDR] {
			continue
		}

		answered, undelivered, err := SweepContext(ctx, attachment.Net, time.Until(deadline))

		// Read *after* the sweep, never before: a probe that gets an answer also fills
		// the kernel's ARP cache, so this is where the MAC addresses of the hosts that
		// just replied come from. Reading first would leave every newly discovered host
		// without a MAC, and it would be filed under its address — then under its MAC
		// on the next pass, as a second device.
		neighbours := neighboursIn(attachment.Net)

		switch {
		case errors.Is(err, ErrNoProbe):
			result.Degraded = true
			result.Failures = append(result.Failures, fmt.Errorf("sweeping %s: %w", attachment.CIDR, err))
		case err != nil:
			// A sweep that fails for any other reason is worth surfacing rather than
			// silently reporting a smaller network than there is.
			result.Failures = append(result.Failures, fmt.Errorf("sweeping %s: %w", attachment.CIDR, err))
			for _, ip := range answered {
				if !isEdgeAddress(ip, attachment.Net) {
					record(seen, ip, neighbours[ip.String()])
				}
			}
		default:
			// Presence is what answered the probe. The neighbour table is consulted
			// only to put a MAC address on those answers — never to add a host of its
			// own, because its entries outlive the devices they describe.
			for _, ip := range answered {
				if isEdgeAddress(ip, attachment.Net) {
					continue
				}

				record(seen, ip, neighbours[ip.String()])
			}

			if undelivered > 0 {
				// Some hosts were never asked, so this is not a picture anyone may
				// draw conclusions from. What was seen is still reported — a device
				// that answered is a device that is there — but the network is not
				// claimed as covered.
				result.Failures = append(result.Failures, fmt.Errorf(
					"sweeping %s: %d probe(s) never left the host, so the network is only partly covered",
					attachment.CIDR, undelivered,
				))

				continue
			}

			result.Scanned = append(result.Scanned, attachment.CIDR)
		}
	}

	addresses := make([]string, 0, len(seen))
	for address := range seen {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)

	// Naming is best effort and never blocks the report: a device without a name is
	// still a device, and the server labels it by its address.
	for address, name := range resolveNamesContext(ctx, addresses, max(0, time.Until(deadline))) {
		seen[address].Hostname = name
	}

	for _, address := range addresses {
		result.Devices = append(result.Devices, *seen[address])
	}

	return result, nil
}

// isEdgeAddress reports whether an address is the network or broadcast address of its
// subnet. Neither is a host, and the broadcast one appears in every ARP table.
func isEdgeAddress(ip net.IP, network *net.IPNet) bool {
	address := ip.To4()
	if address == nil {
		return false
	}

	ones, bits := network.Mask.Size()
	if bits != 32 || bits-ones < 2 {
		return false
	}

	base := network.IP.Mask(network.Mask).To4()
	if base == nil {
		return false
	}

	value := uint32(address[0])<<24 | uint32(address[1])<<16 | uint32(address[2])<<8 | uint32(address[3])
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	last := start + (uint32(1) << uint(bits-ones)) - 1

	return value == start || value == last
}

// neighboursIn reads the operating system's neighbour table, keyed by address, for the
// hosts of one network. It is a source of MAC addresses, not of presence.
func neighboursIn(network *net.IPNet) map[string]string {
	found := map[string]string{}

	for _, neighbor := range Neighbors() {
		if network.Contains(neighbor.IP) && !isEdgeAddress(neighbor.IP, network) {
			found[neighbor.IP.String()] = neighbor.MAC
		}
	}

	return found
}

// record merges what we know about one address, never downgrading a MAC we already have
// to the empty string a plain ICMP answer carries.
func record(seen map[string]*Device, ip net.IP, mac string) {
	if !IsPrivate(ip) || ip.IsMulticast() {
		return
	}

	address := ip.String()

	existing, ok := seen[address]
	if !ok {
		seen[address] = &Device{IP: address, MAC: mac}

		return
	}

	if existing.MAC == "" {
		existing.MAC = mac
	}
}
