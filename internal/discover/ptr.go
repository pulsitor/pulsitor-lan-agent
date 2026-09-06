package discover

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// ptrConcurrency bounds how many reverse lookups run at once. A sweep of a /24 that
// fired 254 simultaneous queries would be indistinguishable from an attack on the
// resolver, and most of them time out anyway on a network with no reverse zone.
const ptrConcurrency = 16

// resolveNames fills in hostnames by asking the resolver what each address is called.
//
// On a home or office network the router usually serves reverse records for its DHCP
// clients, which is where most of these names come from. A network without a reverse
// zone simply yields nothing, and the devices keep their addresses as their labels.
func resolveNames(devices []string, timeout time.Duration) map[string]string {
	return resolveNamesContext(context.Background(), devices, timeout)
}

func resolveNamesContext(parent context.Context, devices []string, timeout time.Duration) map[string]string {
	names := map[string]string{}

	if len(devices) == 0 {
		return names
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	var (
		guard   sync.Mutex
		waiting sync.WaitGroup
	)

	slots := make(chan struct{}, ptrConcurrency)
	resolver := &net.Resolver{}

	for _, address := range devices {
		waiting.Add(1)

		go func(address string) {
			defer waiting.Done()

			slots <- struct{}{}
			defer func() { <-slots }()

			found, err := resolver.LookupAddr(ctx, address)
			if err != nil || len(found) == 0 {
				return
			}

			name := strings.TrimSuffix(found[0], ".")
			if name == "" {
				return
			}

			guard.Lock()
			names[address] = name
			guard.Unlock()
		}(address)
	}

	waiting.Wait()

	return names
}
