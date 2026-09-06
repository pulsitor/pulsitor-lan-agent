package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pulsitor/pulsitor-lan-agent/internal/config"
	"github.com/pulsitor/pulsitor-lan-agent/internal/discover"
	"github.com/pulsitor/pulsitor-lan-agent/internal/report"
)

// origin is the instant every simulated run starts from.
var origin = time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)

// clock is simulated time. Sleeping moves it forward, so a whole minute of scheduling
// runs in microseconds and the assertions are exact rather than approximate.
type clock struct {
	now      time.Time
	deadline time.Time
	stop     context.CancelFunc
}

func (c *clock) Now() time.Time {
	return c.now
}

func (c *clock) Sleep(duration time.Duration) {
	if duration <= 0 {
		duration = time.Millisecond
	}

	c.advance(duration)
}

func (c *clock) advance(duration time.Duration) {
	c.now = c.now.Add(duration)

	if !c.now.Before(c.deadline) {
		c.stop()
	}
}

// harness is one simulated agent talking to one fake server.
type harness struct {
	clock   *clock
	runtime config.Runtime
	reports []report.Report

	// answers decides which addresses reply to a probe.
	answers map[string]bool

	// logger captures the agent's output when a test asserts on what it said.
	logger *log.Logger

	// neighbours stands in for the kernel's table, address to MAC.
	neighbours map[string]string

	// tableReads counts how often that table was read, which on BSD is a process each.
	tableReads int

	// probeError is what the ICMP layer refuses with, if anything.
	probeError error

	// discovered is what a sweep finds.
	discovered discover.Result

	// probeCost is how much simulated time one probe round takes.
	probeCost time.Duration

	probes [][]string
	sweeps int
}

// run drives the agent for a simulated span and returns everything it reported.
func (h *harness) run(t *testing.T, span time.Duration) []report.Report {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		sent := report.Report{}
		if err := json.Unmarshal(body, &sent); err != nil {
			t.Errorf("agent sent a body that is not a report: %v", err)
		}
		h.reports = append(h.reports, sent)

		response, _ := json.Marshal(map[string]any{"config": h.runtime})
		_, _ = w.Write(response)
	}))
	defer server.Close()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	h.clock = &clock{now: origin, deadline: origin.Add(span), stop: stop}

	if h.logger == nil {
		h.logger = log.New(io.Discard, "", 0)
	}

	runner := &Runner{
		Client:    report.New(server.URL, "test"),
		StatePath: t.TempDir() + "/identity.json",
		Network: Network{
			Discover: func(subnets []string, timeout time.Duration) (discover.Result, error) {
				h.sweeps++

				return h.discovered, nil
			},
			Neighbours: func() []discover.Neighbor {
				h.tableReads++

				entries := []discover.Neighbor{}
				for address, mac := range h.neighbours {
					entries = append(entries, discover.Neighbor{IP: net.ParseIP(address), MAC: mac})
				}

				return entries
			},
			Probe: func(hosts []net.IP, timeout time.Duration) ([]net.IP, error) {
				asked := make([]string, 0, len(hosts))
				for _, host := range hosts {
					asked = append(asked, host.String())
				}
				h.probes = append(h.probes, asked)

				if h.probeCost > 0 {
					h.clock.advance(h.probeCost)
				}

				if h.probeError != nil {
					return nil, h.probeError
				}

				replied := []net.IP{}
				for _, host := range hosts {
					if h.answers[host.String()] {
						replied = append(replied, host)
					}
				}

				return replied, nil
			},
		},
		Clock:   Clock{Now: h.clock.Now, Sleep: h.clock.Sleep},
		Logger:  h.logger,
		Backoff: func(int) time.Duration { return time.Second },
		// A fixed phase keeps the grid on round numbers, so the assertions below can
		// name exact instants rather than approximate ones.
		Phase: func(string) time.Duration { return 0 },
	}

	state := &config.State{
		Identity: &config.Identity{Code: "test-agent", Secret: "s3cret"},
		Runtime:  cloneRuntime(h.runtime),
	}

	if err := runner.Run(ctx, state, false); err != nil {
		t.Fatalf("run: %v", err)
	}

	return h.reports
}

// cloneRuntime hands the runner its own copy, so the harness can keep serving the
// original without the two aliasing.
func cloneRuntime(runtime config.Runtime) *config.Runtime {
	copied := runtime
	copied.Subnets = append([]string(nil), runtime.Subnets...)
	copied.Targets = append([]config.Target(nil), runtime.Targets...)

	return &copied
}

// observationsFor collects one target's observations, in the order they were sent.
func observationsFor(reports []report.Report, id int64) []report.Observation {
	found := []report.Observation{}

	for _, sent := range reports {
		for _, observation := range sent.Observations {
			if observation.ID == id {
				found = append(found, observation)
			}
		}
	}

	return found
}

// timesFor collects when a target was observed.
func timesFor(t *testing.T, reports []report.Report, id int64) []time.Time {
	t.Helper()

	found := []time.Time{}

	for _, sent := range reports {
		for _, observation := range sent.Observations {
			if observation.ID != id {
				continue
			}

			at, err := time.Parse(time.RFC3339, sent.ObservedAt)
			if err != nil {
				t.Fatalf("observed_at is not RFC3339: %v", err)
			}

			found = append(found, at)
		}
	}

	return found
}

// Each monitoring runs on its own clock. A device the owner wants checked every fifteen
// seconds must not drag a once-an-hour device along with it, and the reverse must not
// slow it down.
func TestEachTargetKeepsItsOwnInterval(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 300,
			CheckInIntervalSeconds:   60,
			Subnets:                  []string{"192.168.1.0/24"},
			Targets: []config.Target{
				{ID: 1, IP: "192.168.1.10", IntervalSeconds: 15},
				{ID: 2, IP: "192.168.1.20", IntervalSeconds: 60},
			},
		},
		answers: map[string]bool{"192.168.1.10": true, "192.168.1.20": true},
	}

	reports := h.run(t, time.Minute)

	if got := len(observationsFor(reports, 1)); got != 4 {
		t.Errorf("a fifteen second target should be probed 4 times a minute, got %d", got)
	}

	if got := len(observationsFor(reports, 2)); got != 1 {
		t.Errorf("a sixty second target should be probed once a minute, got %d", got)
	}
}

// Discovery is inventory work on its own slow clock: it must not run once per probe.
func TestDiscoveryDoesNotFollowTheProbeInterval(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 300,
			CheckInIntervalSeconds:   60,
			Subnets:                  []string{"192.168.1.0/24"},
			Targets:                  []config.Target{{ID: 1, IP: "192.168.1.10", IntervalSeconds: 15}},
		},
		answers: map[string]bool{"192.168.1.10": true},
	}

	reports := h.run(t, time.Minute)

	if h.sweeps != 1 {
		t.Errorf("discovery should have run once in a minute, ran %d times", h.sweeps)
	}

	carried := 0
	for _, sent := range reports {
		if sent.Devices != nil {
			carried++
		}
	}

	if carried != 1 {
		t.Errorf("only the discovery round should carry an inventory, %d rounds did", carried)
	}
}

// The interval is measured from when a round was due, not from when it finished.
// Sleeping for the interval after the work would make the real period "interval plus
// however long the round took" — a quarter of drift at fifteen seconds, walking every
// sample towards the server's deadline.
func TestIntervalDoesNotDriftWhenWorkIsSlow(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 300,
			CheckInIntervalSeconds:   60,
			Targets:                  []config.Target{{ID: 1, IP: "192.168.1.10", IntervalSeconds: 15}},
		},
		answers:   map[string]bool{"192.168.1.10": true},
		probeCost: 4 * time.Second,
	}

	observed := timesFor(t, h.run(t, time.Minute), 1)

	if len(observed) < 3 {
		t.Fatalf("expected several observations, got %d", len(observed))
	}

	for index := 1; index < len(observed); index++ {
		if gap := observed[index].Sub(observed[index-1]); gap != 15*time.Second {
			t.Fatalf("observation %d came %s after the previous one, not 15s", index, gap)
		}
	}
}

// A device that moved is a device that moved, not a device that vanished. The kernel
// already knows the new address whenever something on the segment has talked to it, so
// the outage must never be reported in the first place.
func TestAMovedDeviceIsFollowedThroughTheNeighbourTable(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 300,
			CheckInIntervalSeconds:   60,
			Targets: []config.Target{
				{ID: 1, IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", IntervalSeconds: 60},
			},
		},
		answers:    map[string]bool{"192.168.1.99": true},
		neighbours: map[string]string{"192.168.1.99": "aa:bb:cc:dd:ee:ff"},
	}

	got := observationsFor(h.run(t, 30*time.Second), 1)

	if len(got) != 1 {
		t.Fatalf("expected one observation, got %d", len(got))
	}

	if !got[0].Online {
		t.Fatal("a device that answered at a new address was reported offline")
	}

	if got[0].IP != "192.168.1.99" {
		t.Fatalf("expected the new address to be reported, got %q", got[0].IP)
	}
}

// When the neighbour table has nothing either, a sweep is what finds the device — and
// it has to happen in the same round, or the move is reported as an outage first.
func TestAnUnaccountedTargetTriggersASweepThatRescuesIt(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds:    300,
			DiscoveryMinIntervalSeconds: 60,
			CheckInIntervalSeconds:      60,
			Subnets:                     []string{"192.168.1.0/24"},
			Targets: []config.Target{
				{ID: 1, IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", IntervalSeconds: 60},
			},
		},
		answers:    map[string]bool{},
		neighbours: map[string]string{},
		discovered: discover.Result{
			Interfaces: []discover.Interface{{Name: "en0", CIDR: "192.168.1.0/24"}},
			Devices: []discover.Device{
				{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.77", Hostname: "nas.lan"},
			},
		},
	}

	got := observationsFor(h.run(t, 90*time.Second), 1)

	if len(got) < 2 {
		t.Fatalf("expected the scheduled and the second round, got %d observations", len(got))
	}

	// The first round is the scheduled discovery, which already finds the device.
	// The second is the one that had to ask for a sweep of its own.
	last := got[len(got)-1]

	if !last.Online {
		t.Fatal("a device a sweep found was still reported offline")
	}

	if last.IP != "192.168.1.77" {
		t.Fatalf("expected the address the sweep found, got %q", last.IP)
	}

	if h.sweeps < 2 {
		t.Errorf("expected an extra sweep to be requested, ran %d", h.sweeps)
	}
}

// A device moves once. One that has been gone for a week must not buy a subnet scan
// every minute for the rest of its life.
func TestALongGoneTargetStopsAskingForSweeps(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds:    3600,
			DiscoveryMinIntervalSeconds: 60,
			CheckInIntervalSeconds:      60,
			Subnets:                     []string{"192.168.1.0/24"},
			Targets: []config.Target{
				{ID: 1, IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", IntervalSeconds: 60},
			},
		},
		answers:    map[string]bool{},
		neighbours: map[string]string{},
	}

	h.run(t, 10*time.Minute)

	// The scheduled sweep, plus the one round that saw the device go quiet.
	if h.sweeps > 2 {
		t.Errorf("a long-gone device kept asking for sweeps: %d in ten minutes", h.sweeps)
	}
}

// The networks a sweep covered travel with it. Without them the server cannot tell
// "looked and did not find it" from "never looked", and one short sweep would walk a
// whole subnet offline.
func TestTheCoveredNetworksTravelWithTheInventory(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 300,
			CheckInIntervalSeconds:   3600,
			Subnets:                  []string{"192.168.1.0/24", "10.20.30.0/24"},
		},
		discovered: discover.Result{
			Interfaces: []discover.Interface{
				{Name: "eth0", CIDR: "192.168.1.0/24"},
				{Name: "eth1", CIDR: "10.20.30.0/24"},
			},
			Devices: []discover.Device{{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.10"}},
			// The second network could not be covered this round.
			Scanned: []string{"192.168.1.0/24"},
		},
	}

	reports := h.run(t, 30*time.Second)

	if len(reports) != 1 || reports[0].Scanned == nil {
		t.Fatalf("the covered networks were not reported: %+v", reports)
	}

	if got := *reports[0].Scanned; len(got) != 1 || got[0] != "192.168.1.0/24" {
		t.Fatalf("expected only the covered network, got %v", got)
	}
}

// A round in which discovery found nothing at all must still say so, rather than
// leaving the server to guess. An empty list is a statement; a missing one is not.
func TestACoveredNetworkWithNothingInItStillReportsItself(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 300,
			CheckInIntervalSeconds:   3600,
			Subnets:                  []string{"192.168.1.0/24"},
		},
		discovered: discover.Result{
			Interfaces: []discover.Interface{{Name: "eth0", CIDR: "192.168.1.0/24"}},
			Devices:    []discover.Device{},
			Scanned:    []string{"192.168.1.0/24"},
		},
	}

	reports := h.run(t, 30*time.Second)

	if reports[0].Devices == nil || len(*reports[0].Devices) != 0 {
		t.Fatalf("an empty sweep must still carry an empty device list: %+v", reports[0].Devices)
	}

	if reports[0].Scanned == nil || len(*reports[0].Scanned) != 1 {
		t.Fatalf("an empty sweep must still name what it covered: %+v", reports[0].Scanned)
	}
}

// An unavailable probe must report neither stale presence nor fabricated absence.
func TestAnAgentThatCannotProbeOmitsObservations(t *testing.T) {
	h := &harness{runtime: config.Runtime{DiscoveryIntervalSeconds: 300, CheckInIntervalSeconds: 60,
		Targets: []config.Target{{ID: 1, IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", IntervalSeconds: 60}, {ID: 2, IP: "192.168.1.20", IntervalSeconds: 60}}},
		probeError: discover.ErrNoProbe, neighbours: map[string]string{"192.168.1.10": "aa:bb:cc:dd:ee:ff"}}
	for _, report := range h.run(t, 30*time.Second) {
		if len(report.Observations) > 0 {
			t.Fatalf("unverified observations: %+v", report.Observations)
		}
	}
}

// The kernel's table is read once per round, however many devices are being watched.
// On BSD that read is a process, so doing it per device would mean one arp(8) per
// device per round — two hundred processes a minute for fifty devices at fifteen
// seconds.
func TestTheNeighbourTableIsReadOncePerRound(t *testing.T) {
	targets := []config.Target{}
	answers := map[string]bool{}

	for id := 1; id <= 10; id++ {
		address := fmt.Sprintf("192.168.1.%d", 10+id)
		targets = append(targets, config.Target{
			ID:              int64(id),
			IP:              address,
			MAC:             fmt.Sprintf("aa:bb:cc:dd:ee:%02x", id),
			IntervalSeconds: 60,
		})
		answers[address] = true
	}

	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 3600,
			CheckInIntervalSeconds:   3600,
			Targets:                  targets,
		},
		answers:    answers,
		neighbours: map[string]string{},
	}

	h.run(t, 30*time.Second)

	if h.tableReads != 1 {
		t.Errorf("ten devices in one round cost %d table reads, not 1", h.tableReads)
	}
}

// An address is not an identity. A DHCP lease gets handed on, and the machine that
// picks it up answers a probe exactly as the old one did — reporting that as the
// monitored device being up would hide a real outage, which is the worst thing a
// monitor can do.
func TestAnAnswerFromTheWrongDeviceIsNotAnAnswer(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds:    300,
			DiscoveryMinIntervalSeconds: 60,
			CheckInIntervalSeconds:      60,
			Targets: []config.Target{
				{ID: 1, IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", IntervalSeconds: 60},
			},
		},
		// Something answers at the monitored address, but the lease has moved on.
		answers:    map[string]bool{"192.168.1.10": true},
		neighbours: map[string]string{"192.168.1.10": "98:88:77:66:55:44"},
	}

	got := observationsFor(h.run(t, 30*time.Second), 1)

	if len(got) != 1 {
		t.Fatalf("expected one observation, got %d", len(got))
	}

	if got[0].Online {
		t.Fatal("a reply from a different device was reported as the monitored one being up")
	}
}

// The check must not invent an outage when the kernel simply has no entry for the
// address — that is the ordinary case on a segment the agent has only just joined.
func TestAnAnswerIsTrustedWhenNobodyCanSayWhoHoldsTheAddress(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 300,
			CheckInIntervalSeconds:   60,
			Targets: []config.Target{
				{ID: 1, IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", IntervalSeconds: 60},
			},
		},
		answers:    map[string]bool{"192.168.1.10": true},
		neighbours: map[string]string{},
	}

	got := observationsFor(h.run(t, 30*time.Second), 1)

	if len(got) != 1 || !got[0].Online {
		t.Fatalf("a device that answered was not reported up: %+v", got)
	}
}

// A device that is genuinely gone must be reported as gone, not endlessly excused.
func TestADeviceThatAnswersNowhereIsReportedOffline(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 300,
			CheckInIntervalSeconds:   60,
			Targets: []config.Target{
				{ID: 1, IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", IntervalSeconds: 60},
			},
		},
		answers:    map[string]bool{},
		neighbours: map[string]string{},
	}

	got := observationsFor(h.run(t, 30*time.Second), 1)

	if len(got) != 1 {
		t.Fatalf("expected one observation, got %d", len(got))
	}

	if got[0].Online {
		t.Fatal("a device that answered nowhere was reported online")
	}

	if got[0].IP != "" {
		t.Fatalf("an offline observation must carry no address, got %q", got[0].IP)
	}
}

// An agent whose only device is checked once an hour must not be silent for an hour.
// It learns its schedule from the response to its own report, so staying quiet means
// never hearing about a change — and looking dead in the meantime.
func TestTheAgentChecksInEvenWithNothingToReport(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 3600,
			CheckInIntervalSeconds:   60,
			Targets:                  []config.Target{{ID: 1, IP: "192.168.1.10", IntervalSeconds: 3600}},
		},
		answers: map[string]bool{"192.168.1.10": true},
	}

	reports := h.run(t, 5*time.Minute)

	if len(reports) != 5 {
		t.Fatalf("expected a report a minute, got %d", len(reports))
	}

	// Only the first round had work to do; the rest are pure check-ins.
	if got := len(observationsFor(reports, 1)); got != 1 {
		t.Errorf("an hourly target should have been probed once, got %d", got)
	}

	if h.sweeps != 1 {
		t.Errorf("an hourly discovery should have run once, ran %d times", h.sweeps)
	}
}

// A target the server stops sending must stop costing packets at once, and a new one
// must not wait a whole interval for its first sample.
func TestTheTargetListFollowsTheServer(t *testing.T) {
	schedule := New(&config.Runtime{
		DiscoveryIntervalSeconds: 300,
		Targets:                  []config.Target{{ID: 1, IP: "192.168.1.10", IntervalSeconds: 60}},
	}, origin, 0)

	schedule.CompletedTarget(config.Target{ID: 1, IntervalSeconds: 60}, origin)

	schedule.Apply(&config.Runtime{
		DiscoveryIntervalSeconds: 300,
		Targets:                  []config.Target{{ID: 2, IP: "192.168.1.20", IntervalSeconds: 60}},
	}, origin)

	_, due := schedule.Due(origin)

	if len(due) != 1 || due[0].ID != 2 {
		t.Fatalf("a freshly added target should be due at once, got %+v", due)
	}
}

// Devices sharing an interval must be probed in the same round, whenever they were
// added. Giving each target its own phase would mean an agent watching fifty devices on
// a sixty second check sending fifty reports a minute instead of one — past its own
// rate limit, and the monitoring would start failing on 429s.
func TestTargetsOnTheSameIntervalShareTheirRounds(t *testing.T) {
	one := &config.Runtime{
		DiscoveryIntervalSeconds: 3600,
		CheckInIntervalSeconds:   3600,
		Targets:                  []config.Target{{ID: 1, IP: "10.0.0.1", IntervalSeconds: 60}},
	}

	schedule := New(one, origin, 0)
	schedule.CompletedTarget(one.Targets[0], origin)

	// Seven seconds later the owner adds a second device on the same interval.
	added := origin.Add(7 * time.Second)

	two := &config.Runtime{
		DiscoveryIntervalSeconds: 3600,
		CheckInIntervalSeconds:   3600,
		Targets: []config.Target{
			{ID: 1, IP: "10.0.0.1", IntervalSeconds: 60},
			{ID: 2, IP: "10.0.0.2", IntervalSeconds: 60},
		},
	}

	schedule.Apply(two, added)
	schedule.CompletedTarget(two.Targets[1], added)

	rounds := 0
	now := added.Add(time.Second)
	end := origin.Add(10 * time.Minute)

	for now.Before(end) {
		if _, due := schedule.Due(now); len(due) > 0 {
			rounds++

			for _, target := range due {
				schedule.CompletedTarget(target, now)
			}
		}

		wait := schedule.Wait(now)
		if wait <= 0 {
			wait = time.Second
		}

		now = now.Add(wait)
	}

	if rounds > 11 {
		t.Errorf("two targets on one interval cost %d rounds in ten minutes, not ~10", rounds)
	}
}

// A clock that steps backwards must not silence the agent. These run on machines with
// no battery-backed clock, where an NTP correction of hours at boot is ordinary.
func TestABackwardClockStepDoesNotSilenceTheAgent(t *testing.T) {
	runtime := &config.Runtime{
		DiscoveryIntervalSeconds: 300,
		CheckInIntervalSeconds:   60,
		Targets:                  []config.Target{{ID: 1, IP: "10.0.0.1", IntervalSeconds: 60}},
	}

	schedule := New(runtime, origin, 0)
	schedule.CompletedTarget(runtime.Targets[0], origin)
	schedule.CompletedCheckIn(origin)
	schedule.CompletedDiscovery(origin)

	// The clock is corrected two hours back.
	stepped := origin.Add(-2 * time.Hour)

	if !schedule.Reconcile(stepped) {
		t.Fatal("a two hour backward step went unnoticed")
	}

	if wait := schedule.Wait(stepped); wait > time.Minute {
		t.Fatalf("the agent would have stayed silent for %s after the step", wait)
	}

	// The sweep really did happen moments ago in real time, so an extra one is still
	// held off — but the scheduled one must come back inside its own interval rather
	// than two hours late.
	if _, due := schedule.Due(stepped.Add(5 * time.Minute)); len(due) == 0 {
		t.Error("the target never came due again after the step")
	}

	if !schedule.CheckInDue(stepped.Add(time.Minute)) {
		t.Error("the agent would not have checked in for two hours after the step")
	}
}

// Shortening a monitoring's interval has to take effect now, not at the slot the old
// one had already claimed. An hourly device moved to fifteen seconds would otherwise go
// unprobed for up to an hour, and the server — already expecting it every fifteen
// seconds — would open an outage for a device that is perfectly fine.
func TestShorteningAnIntervalTakesEffectAtOnce(t *testing.T) {
	hourly := &config.Runtime{
		DiscoveryIntervalSeconds: 300,
		CheckInIntervalSeconds:   60,
		Targets:                  []config.Target{{ID: 1, IP: "10.0.0.1", IntervalSeconds: 3600}},
	}

	schedule := New(hourly, origin, 0)
	schedule.CompletedTarget(hourly.Targets[0], origin)

	if due := schedule.TargetDueAt(1).Sub(origin); due < 30*time.Minute {
		t.Fatalf("an hourly target should be an hour away, not %s", due)
	}

	quick := &config.Runtime{
		DiscoveryIntervalSeconds: 300,
		CheckInIntervalSeconds:   60,
		Targets:                  []config.Target{{ID: 1, IP: "10.0.0.1", IntervalSeconds: 15}},
	}

	schedule.Apply(quick, origin)
	schedule.Reconcile(origin)

	if due := schedule.TargetDueAt(1).Sub(origin); due > 15*time.Second {
		t.Fatalf("the shortened interval did not take hold: next probe in %s", due)
	}
}

// Falling far behind must not turn into a burst of probes describing a moment that has
// already gone.
func TestFallingBehindSkipsSlotsInsteadOfCatchingUp(t *testing.T) {
	schedule := New(&config.Runtime{
		DiscoveryIntervalSeconds: 300,
		Targets:                  []config.Target{{ID: 1, IP: "192.168.1.10", IntervalSeconds: 15}},
	}, origin, 0)

	// The round was due at the origin but only finished a minute later.
	late := origin.Add(time.Minute)

	skipped := schedule.CompletedTarget(config.Target{ID: 1, IntervalSeconds: 15}, late)

	if skipped != 4 {
		t.Errorf("expected 4 skipped slots, got %d", skipped)
	}

	if _, due := schedule.Due(late); len(due) != 0 {
		t.Error("the target should not be due again immediately after falling behind")
	}
}

func TestProbeFailureDoesNotReportDeviceOffline(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds: 300,
			CheckInIntervalSeconds:   60,
			Targets:                  []config.Target{{ID: 1, IP: "192.168.1.10", IntervalSeconds: 15}},
		},
		probeError: fmt.Errorf("ICMP probe could not be sent"),
	}
	reports := h.run(t, time.Minute)
	if len(reports) == 0 {
		t.Fatal("agent did not check in after a local probe failure")
	}
	for _, report := range reports {
		if len(report.Observations) != 0 {
			t.Fatalf("failed probe invented an observation: %+v", report.Observations)
		}
	}
}

func TestPartialProbeFailureKeepsOnlyConfirmedAnswers(t *testing.T) {
	runner := &Runner{
		Logger: log.New(io.Discard, "", 0),
		Network: Network{
			Probe: func([]net.IP, time.Duration) ([]net.IP, error) {
				return []net.IP{net.ParseIP("192.168.1.10")}, fmt.Errorf("one send failed")
			},
			Neighbours: func() []discover.Neighbor { return nil },
		},
	}
	observations, unresolved := runner.probeTargets([]config.Target{
		{ID: 1, IP: "192.168.1.10"}, {ID: 2, IP: "192.168.1.20"},
	})
	if len(observations) != 1 || !observations[1].Online || len(unresolved) != 0 {
		t.Fatalf("partial send failure became negative evidence: %+v, %+v", observations, unresolved)
	}
}

func TestFailedProbeAtMovedAddressDoesNotInventAnOutage(t *testing.T) {
	calls := 0
	runner := &Runner{
		Logger: log.New(io.Discard, "", 0),
		Network: Network{
			Probe: func([]net.IP, time.Duration) ([]net.IP, error) {
				calls++
				if calls == 1 {
					return nil, nil
				}
				return nil, fmt.Errorf("candidate probe failed")
			},
			Neighbours: func() []discover.Neighbor {
				return []discover.Neighbor{{IP: net.ParseIP("192.168.1.55"), MAC: "aa:bb:cc:dd:ee:ff"}}
			},
		},
	}
	observations, unresolved := runner.probeTargets([]config.Target{
		{ID: 1, IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff"},
	})
	if calls != 2 || len(observations) != 0 || len(unresolved) != 0 {
		t.Fatalf("failed candidate probe became an outage: %+v, %+v", observations, unresolved)
	}
}

// An agent whose identity the owner deleted is refused identically forever. Retrying it
// on the ordinary curve means five requests a minute, from every abandoned agent in the
// fleet, for as long as the machine stays switched on.
func TestATerminalRefusalGoesStraightToTheSlowestRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"agent_mismatch","message":"Unknown agent."}`))
	}))
	defer server.Close()

	attempts := []int{}
	written := &strings.Builder{}

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	runner := &Runner{
		Client:    report.New(server.URL, "test"),
		StatePath: t.TempDir() + "/identity.json",
		Network: Network{
			Discover:   func([]string, time.Duration) (discover.Result, error) { return discover.Result{}, nil },
			Probe:      func([]net.IP, time.Duration) ([]net.IP, error) { return nil, nil },
			Neighbours: func() []discover.Neighbor { return nil },
		},
		Clock:  Clock{Now: func() time.Time { return origin }, Sleep: func(time.Duration) {}},
		Logger: log.New(written, "", 0),
		Backoff: func(attempt int) time.Duration {
			attempts = append(attempts, attempt)

			if len(attempts) == 2 {
				stop()
			}

			return 0
		},
		Phase: func(string) time.Duration { return 0 },
	}

	state := &config.State{Identity: &config.Identity{Code: "test-agent", Secret: "s3cret"}}

	if err := runner.Run(ctx, state, false); err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(attempts) < 2 {
		t.Fatalf("expected at least two retries, got %v", attempts)
	}

	for _, attempt := range attempts {
		if attempt < terminalFailure {
			t.Fatalf("a terminal refusal was retried at attempt %d, which is not the ceiling", attempt)
		}
	}

	// The operator has to be told what to do about it, not just that it failed.
	if !strings.Contains(written.String(), "enrol again from Pulsitor") {
		t.Fatalf("the log does not say how to fix it:\n%s", written)
	}
}

// A healthy agent on a fifteen second check runs nearly six thousand rounds a day. If
// every one of them wrote a line, the one round that mattered would be unfindable.
func TestOnlyRoundsThatCarriedNewsAreLogged(t *testing.T) {
	runner := &Runner{}

	up := []report.Observation{{ID: 1, Online: true}}

	if !runner.noteAnswers(up) {
		t.Fatal("the first answer for a target is always news")
	}

	if runner.noteAnswers(up) {
		t.Fatal("a device that answered exactly as it did before is not news")
	}

	down := []report.Observation{{ID: 1, Online: false}}

	if !runner.noteAnswers(down) {
		t.Fatal("a device going offline is news")
	}

	// Still down is not news. The server holds the incident; repeating it here every
	// fifteen seconds would bury the rounds that did change something.
	if runner.noteAnswers(down) {
		t.Fatal("an unchanged ongoing outage was logged again")
	}

	if !runner.noteAnswers(up) {
		t.Fatal("a device coming back is news")
	}

	// A target nobody has seen before is news even when it answers.
	if !runner.noteAnswers([]report.Observation{{ID: 1, Online: true}, {ID: 2, Online: true}}) {
		t.Fatal("a target's first round is news")
	}
}

func TestVerboseDecidesWhetherDetailIsWritten(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		written := &strings.Builder{}

		runner := &Runner{Logger: log.New(written, "", 0), Verbose: verbose}
		runner.debugf("detail")

		if (written.Len() > 0) != verbose {
			t.Fatalf("verbose=%v wrote %q", verbose, written)
		}
	}
}

// A device whose subnet the agent has left sits outside every attached network, and the
// server keeps handing back its last known address until the agent manages to say
// something about it. If that counted as a broken probe, the round would take the
// cautious path — positives only — and no *other* device on this agent would ever be
// reported offline again, for as long as the stale one stayed stale.
func TestAStaleOffLanTargetDoesNotSilenceTheRest(t *testing.T) {
	written := &strings.Builder{}

	runner := &Runner{
		Logger: log.New(written, "", 0),
		Network: Network{
			Probe: func(hosts []net.IP, _ time.Duration) ([]net.IP, error) {
				// What ProbeLocal does when one target is off-LAN: the reachable ones
				// are probed, and the skipped one is reported apart from the result.
				return []net.IP{net.ParseIP("192.168.1.10")}, discover.ErrOffLAN
			},
			Neighbours: func() []discover.Neighbor { return nil },
		},
	}

	observations, unresolved := runner.probeTargets([]config.Target{
		{ID: 1, IP: "192.168.1.10"}, // reachable, answering
		{ID: 2, IP: "192.168.1.20"}, // reachable, silent
		{ID: 3, IP: "10.9.9.9"},     // the stale one, on a network we have left
	})

	if len(observations) != 3 {
		t.Fatalf("expected a verdict for every target, got %d: %+v", len(observations), observations)
	}

	if !observations[1].Online {
		t.Fatal("the device that answered was not reported online")
	}

	// The whole point: a silent device is still reported silent.
	if observations[2].Online {
		t.Fatal("a silent device was reported online")
	}

	if observations[3].Online {
		t.Fatal("a target on an unattached network was reported online")
	}

	// Both silent devices go to the sweep, which is how one that merely moved is found
	// again at its new address instead of staying an outage.
	if len(unresolved) != 2 {
		t.Fatalf("expected both silent targets to be looked for, got %d", len(unresolved))
	}

	if !strings.Contains(written.String(), "no longer on any network") {
		t.Fatalf("the operator was not told why: %s", written)
	}
}

// A genuine send failure must still take the cautious path: a host nobody managed to ask
// has not been found missing.
func TestARealSendFailureStillReportsPositivesOnly(t *testing.T) {
	runner := &Runner{
		Logger: log.New(io.Discard, "", 0),
		Network: Network{
			Probe: func([]net.IP, time.Duration) ([]net.IP, error) {
				return []net.IP{net.ParseIP("192.168.1.10")}, fmt.Errorf("send buffer full")
			},
			Neighbours: func() []discover.Neighbor { return nil },
		},
	}

	observations, unresolved := runner.probeTargets([]config.Target{
		{ID: 1, IP: "192.168.1.10"}, {ID: 2, IP: "192.168.1.20"},
	})

	if len(observations) != 1 || !observations[1].Online || len(unresolved) != 0 {
		t.Fatalf("a send failure was read as absence: %+v", observations)
	}
}

// The schedule prunes its own per-target maps when a monitoring goes away; this is the
// third one, and a process that runs for a year unattended must not be the only place
// that keeps every target it has ever seen.
func TestRememberedAnswersAreDroppedWithTheirTarget(t *testing.T) {
	runner := &Runner{}

	runner.noteAnswers([]report.Observation{{ID: 1, Online: true}, {ID: 2, Online: true}})

	if len(runner.reported) != 2 {
		t.Fatalf("expected two remembered targets, got %d", len(runner.reported))
	}

	runner.forget([]config.Target{{ID: 2}})

	if _, kept := runner.reported[1]; kept {
		t.Fatal("a target the server stopped sending is still remembered")
	}

	if _, kept := runner.reported[2]; !kept {
		t.Fatal("a live target was forgotten")
	}
}

// A target on a network the agent has left is a standing condition, not an event. Said
// on every probe it would be thousands of identical lines a day; said never, nobody
// would know why a device stopped being reported.
func TestTheOffLanConditionIsReportedOnChangeOnly(t *testing.T) {
	written := &strings.Builder{}
	offLAN := true

	runner := &Runner{
		Logger: log.New(written, "", 0),
		Network: Network{
			Probe: func([]net.IP, time.Duration) ([]net.IP, error) {
				if offLAN {
					return nil, discover.ErrOffLAN
				}

				return []net.IP{net.ParseIP("192.168.1.10")}, nil
			},
			Neighbours: func() []discover.Neighbor { return nil },
		},
	}

	targets := []config.Target{{ID: 1, IP: "192.168.1.10"}}

	for range 5 {
		runner.probeTargets(targets)
	}

	if got := strings.Count(written.String(), "no longer on any network"); got != 1 {
		t.Fatalf("the standing condition was reported %d times, want once:\n%s", got, written)
	}

	offLAN = false

	for range 5 {
		runner.probeTargets(targets)
	}

	if got := strings.Count(written.String(), "back on an attached network"); got != 1 {
		t.Fatalf("the recovery was reported %d times, want once:\n%s", got, written)
	}
}

// The remembered answers are what "changed" is measured against, so they have to be
// updated on every round — including the ones that carried a discovery sweep, which are
// logged for their own reasons and would otherwise skip the recording entirely and leave
// the next probe round convinced every device it had just seen was new.
func TestADiscoveryRoundStillRecordsWhatTheDevicesAnswered(t *testing.T) {
	h := &harness{
		runtime: config.Runtime{
			DiscoveryIntervalSeconds:    30,
			DiscoveryMinIntervalSeconds: 30,
			CheckInIntervalSeconds:      15,
			Subnets:                     []string{"192.168.1.0/24"},
			Targets:                     []config.Target{{ID: 1, IP: "192.168.1.10", IntervalSeconds: 15}},
		},
		answers: map[string]bool{"192.168.1.10": true},
	}

	written := &strings.Builder{}
	h.logger = log.New(written, "", 0)

	h.run(t, 70*time.Second)

	// One line per discovery sweep, plus the first sight of the device. A steady device
	// on a fifteen second check must not add a line every time it answers as before.
	rounds := strings.Count(written.String(), "reported ")

	// Three discovery sweeps in seventy seconds, each logged for its own sake. The
	// probe rounds in between saw the same device answer the same way and must add
	// nothing — a "discovery skipped" line here is the recording having been short-
	// circuited away, leaving that round convinced the device was one it had never seen.
	if skipped := strings.Count(written.String(), "discovery skipped"); skipped != 0 {
		t.Fatalf("%d unchanged probe round(s) were logged as news:\n%s", skipped, written)
	}

	if rounds != 3 {
		t.Fatalf("expected one line per discovery sweep, got %d:\n%s", rounds, written)
	}
}

// Stopping the agent closes the sockets under the round in flight, which produces
// exactly the errors a broken network would. A service manager stops this process on
// every upgrade and every reboot, so reporting those would leave an operator a failure
// to investigate after each one, when all that happened is that we asked it to stop.
func TestShuttingDownIsNotReportedAsAFailure(t *testing.T) {
	written := &strings.Builder{}

	ctx, stop := context.WithCancel(context.Background())
	stop()

	runner := &Runner{
		Logger: log.New(written, "", 0),
		Network: Network{
			ProbeContext: func(context.Context, []net.IP, time.Duration) ([]net.IP, error) {
				return nil, fmt.Errorf("use of closed network connection")
			},
			Neighbours: func() []discover.Neighbor { return nil },
		},
	}

	runner.probeTargetsContext(ctx, []config.Target{{ID: 1, IP: "192.168.1.10"}})

	if written.Len() != 0 {
		t.Fatalf("a shutdown was reported as a failure: %s", written)
	}

	// The same error outside a shutdown is a real failure and must still be reported.
	live := &strings.Builder{}
	runner.Logger = log.New(live, "", 0)

	runner.probeTargetsContext(context.Background(), []config.Target{{ID: 1, IP: "192.168.1.10"}})

	if !strings.Contains(live.String(), "probe failed") {
		t.Fatalf("a genuine probe failure was swallowed: %s", live)
	}
}
