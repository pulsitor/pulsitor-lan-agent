//go:build linux

package discover

import "os"

// Neighbors reads the kernel's ARP table. No packets are sent and no privileges are
// needed, so this is the one discovery step that always works.
func Neighbors() []Neighbor {
	contents, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return []Neighbor{}
	}

	return parseProcNetARP(string(contents))
}
