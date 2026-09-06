package agent

import (
	"errors"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/pulsitor/pulsitor-lan-agent/internal/config"
	"github.com/pulsitor/pulsitor-lan-agent/internal/discover"
)

func TestMovedAddressRequiresFreshMAC(t *testing.T) {
	const wanted = "aa:bb:cc:dd:ee:01"
	for _, test := range []struct {
		name, mac     string
		reply, online bool
		probeError    error
	}{
		{name: "same device", mac: wanted, reply: true, online: true},
		{name: "reassigned address", mac: "aa:bb:cc:dd:ee:02", reply: true},
		{name: "unknown owner", reply: true},
		{name: "silent candidate", mac: wanted},
		{name: "positive answer despite another send failure", mac: wanted, reply: true, online: true, probeError: errors.New("partial send")},
	} {
		t.Run(test.name, func(t *testing.T) {
			probes, reads := 0, 0
			target := config.Target{ID: 1, IP: "192.168.1.10", MAC: wanted, IntervalSeconds: 15}
			candidate := net.ParseIP("192.168.1.20")
			r := &Runner{Logger: log.New(io.Discard, "", 0), Network: Network{
				Probe: func(hosts []net.IP, _ time.Duration) ([]net.IP, error) {
					probes++
					if probes == 1 {
						return nil, nil
					}
					if len(hosts) != 1 || !hosts[0].Equal(candidate) {
						t.Fatalf("unexpected candidates: %v", hosts)
					}
					if test.reply {
						return []net.IP{candidate}, test.probeError
					}
					return nil, test.probeError
				},
				Neighbours: func() []discover.Neighbor {
					reads++
					mac := wanted
					if probes == 2 {
						mac = test.mac
					}
					return []discover.Neighbor{{IP: candidate, MAC: mac}}
				},
			}}
			observations, unresolved := r.probeTargets([]config.Target{target})
			o := observations[target.ID]
			if o == nil || o.Online != test.online {
				t.Fatalf("observation: %+v; want online %v", o, test.online)
			}
			if test.online && o.IP != candidate.String() {
				t.Fatalf("wrong moved IP: %s", o.IP)
			}
			if !test.online && (len(unresolved) != 1 || o.IP != "") {
				t.Fatalf("unverified move lost from discovery: %+v / %+v", o, unresolved)
			}
			if reads != 2 {
				t.Fatalf("want one table read after each probe, got %d", reads)
			}
		})
	}
}
