//go:build darwin || freebsd || openbsd || netbsd

package discover

import (
	"context"
	"os/exec"
	"time"
)

// Neighbors reads the ARP table through the system tool, there being no /proc to read.
func Neighbors() []Neighbor {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, "arp", "-an").Output()
	if err != nil {
		return []Neighbor{}
	}

	return parseArpCommand(string(output))
}
