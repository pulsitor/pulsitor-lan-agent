package agent

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/pulsitor/pulsitor-lan-agent/internal/config"
	"github.com/pulsitor/pulsitor-lan-agent/internal/discover"
	"github.com/pulsitor/pulsitor-lan-agent/internal/report"
)

// Timeouts for the two kinds of network work. They are fixed rather than derived from
// an interval: how long a /22 takes to sweep has nothing to do with how often the owner
// wants it swept, and a monitoring set to once a day must not be given a day-long
// ceiling for a single packet.
const (
	discoveryTimeout = 30 * time.Second
	probeTimeout     = 5 * time.Second
)

// Bounds for the retry delay after a failed report.
const (
	backoffBase = 5 * time.Second
	backoffMax  = 5 * time.Minute
)

// defaultDiscoveryInterval is what a never-configured agent starts on, only until its
// first response arrives.
const defaultDiscoveryInterval = 300

// terminalFailure is the failure count a refusal that will never succeed jumps to, so
// the backoff is already at its ceiling on the first one.
const terminalFailure = 32

// Network is everything the runner needs from the network. They are fields so a test
// can drive a full round without sending a packet.
type Network struct {
	DiscoverContext func(context.Context, []string, time.Duration) (discover.Result, error)
	ProbeContext    func(context.Context, []net.IP, time.Duration) ([]net.IP, error)
	Discover        func(subnets []string, timeout time.Duration) (discover.Result, error)
	Probe           func(hosts []net.IP, timeout time.Duration) ([]net.IP, error)

	// Neighbours is the whole kernel table in one read. On BSD that read shells out to
	// arp(8), so it is read once per probe batch, never once per device. A second
	// batch following moved devices needs a fresh reading to verify their MACs.
	Neighbours func() []discover.Neighbor
}

// neighbours is one reading of the kernel's table, indexed both ways.
type neighbours struct {
	byMAC map[string]net.IP
	byIP  map[string]string
}

// index builds the two lookups from one reading.
func index(entries []discover.Neighbor) neighbours {
	table := neighbours{
		byMAC: make(map[string]net.IP, len(entries)),
		byIP:  make(map[string]string, len(entries)),
	}

	for _, entry := range entries {
		mac := discover.NormaliseMAC(entry.MAC)
		if mac == "" || entry.IP == nil {
			continue
		}

		table.byIP[entry.IP.String()] = mac

		if _, seen := table.byMAC[mac]; !seen {
			table.byMAC[mac] = entry.IP
		}
	}

	return table
}

// holder is the MAC currently at an address, if the kernel knows of one.
func (n neighbours) holder(ip string) (string, bool) {
	mac, ok := n.byIP[ip]

	return mac, ok
}

// whereIs is the address a MAC currently answers at, if the kernel knows of one.
func (n neighbours) whereIs(mac string) (net.IP, bool) {
	ip, ok := n.byMAC[discover.NormaliseMAC(mac)]

	return ip, ok
}

// Clock is time, injected for the same reason.
type Clock struct {
	Now   func() time.Time
	Sleep func(time.Duration)
}

// Runner performs rounds of work until told to stop.
type Runner struct {
	Client    *report.Client
	StatePath string
	Network   Network
	Clock     Clock
	Logger    *log.Logger

	// Verbose logs every round rather than only the ones that carried news. A healthy
	// agent on a fifteen second check runs nearly six thousand rounds a day, so the
	// quiet default is what keeps a year of unattended operation readable — and this is
	// what an operator turns on when they need to see the ones in between.
	Verbose bool

	// Backoff is how long to wait after a consecutive failure. Overridden in tests.
	Backoff func(attempt int) time.Duration

	// Phase spreads this agent's probe grid away from every other agent's. Defaults to
	// one derived from the agent's own identity; overridden in tests.
	Phase func(code string) time.Duration

	// reported is the last answer sent for each target, which is how a round with
	// nothing new in it is told from one worth logging.
	reported map[int64]bool

	// offLAN remembers whether targets were outside every attached network last round,
	// so a standing condition is reported when it changes rather than on every probe.
	offLAN bool
}

// Live builds a runner wired to the real network and the real clock.
func Live(client *report.Client, statePath string) *Runner {
	return &Runner{
		Client:    client,
		StatePath: statePath,
		Network: Network{
			DiscoverContext: discover.RunContext,
			ProbeContext:    discover.ProbeLocalContext,
			Discover:        discover.Run,
			Probe:           discover.ProbeLocal,
			Neighbours:      discover.Neighbors,
		},
		Clock: Clock{Now: time.Now},
	}
}

// Run works until the context is cancelled, or through a single round when once is set.
func (r *Runner) Run(ctx context.Context, state *config.State, once bool) error {
	r.prepare()

	// A first-ever run has nothing to probe: the server owns both the subnet list and
	// the target list, so the agent announces itself and works on whatever comes back.
	if state.Runtime == nil {
		state.Runtime = &config.Runtime{DiscoveryIntervalSeconds: defaultDiscoveryInterval}
	}

	schedule := New(state.Runtime, r.Clock.Now(), r.Phase(state.Identity.Code))
	failures := 0
	persisted := state.Runtime

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		now := r.Clock.Now()

		if schedule.Reconcile(now) {
			r.logf("the clock stepped backwards; the schedule has been pulled back to it")
		}

		discoveryDue, targets := schedule.Due(now)

		// A round with nothing to show for it is still worth sending: the agent's
		// schedule arrives in the response to its own report, so staying quiet means
		// never hearing that anything changed — and looking dead while it waits.
		if !discoveryDue && len(targets) == 0 && !schedule.CheckInDue(now) {
			if once {
				return nil
			}

			r.sleep(ctx, schedule.Wait(now))

			continue
		}

		round := r.round(ctx, schedule, discoveryDue, targets, now)
		if ctx.Err() != nil {
			return nil
		}

		updated, err := r.Client.ReportContext(ctx, state.Identity, round)
		if err != nil {
			// The round's observations are gone with it. That is deliberate: the next
			// round observes afresh, and a stale sample is worse than a missing one.
			r.logf("report failed: %v", err)

			if once {
				return err
			}

			failures++

			// A refusal the server will repeat forever must not be retried on the same
			// curve as a lost connection: the agent goes straight to its slowest
			// interval and says what a person has to do, rather than knocking on a
			// door that has been bricked up.
			var refusal *report.ServerError
			if errors.As(err, &refusal) {
				if advice := refusal.Advice(); advice != "" {
					r.logf("%s", advice)
				}

				if refusal.Terminal() {
					failures = terminalFailure
				}
			}

			r.sleep(ctx, r.Backoff(failures))

			continue
		}

		failures = 0

		schedule.CompletedCheckIn(r.Clock.Now())

		// Evaluated before the decision, never inside it: this records what each device
		// answered, and || short-circuits. Folded into the condition it would be skipped
		// on every discovery round, leaving the remembered answers a round stale and the
		// next probe round convinced that every device it had just seen was new.
		changed := r.noteAnswers(round.Observations)

		summary := func(format string, arguments ...any) { r.debugf(format, arguments...) }
		if round.Devices != nil || changed || !updated.Equal(state.Runtime) {
			summary = r.logf
		}

		summary("reported %d observation(s) over %d target(s); discovery %s",
			len(round.Observations), len(updated.Targets), discoveryState(round))

		state.Runtime = updated
		if !updated.Equal(persisted) {

			if err := config.Save(r.StatePath, state); err != nil {
				r.logf("could not store the new configuration: %v", err)
			} else {
				persisted = updated
			}
		}

		schedule.Apply(state.Runtime, r.Clock.Now())
		r.forget(state.Runtime.Targets)

		if once {
			return nil
		}
	}
}

// round performs everything that is due and returns what to send.
func (r *Runner) round(ctx context.Context, schedule *Schedule, discoveryDue bool, targets []config.Target, now time.Time) report.Report {
	observations, unresolved := r.probeTargetsContext(ctx, targets)

	justMissing := make([]config.Target, 0, len(unresolved))
	for _, target := range unresolved {
		if schedule.WasAnswering(target.ID) {
			justMissing = append(justMissing, target)
		}
	}

	// A target that answered at neither its known address nor the one the neighbour
	// table offers may simply have moved. A sweep is how the agent finds out, and doing
	// it in this same round is what keeps a move from being reported as an outage.
	//
	// Only for a device that has *just* gone quiet, though: a device moves once, and a
	// device that has been gone for a week must not buy a subnet scan every minute for
	// the rest of its life.
	if len(justMissing) > 0 && !discoveryDue && schedule.MayDiscover(now) {
		r.logf("%d target(s) have just gone quiet; sweeping to look for them", len(justMissing))

		discoveryDue = true
	}

	out := report.Report{ObservedAt: now.UTC().Format(time.RFC3339)}

	if discoveryDue {
		var result discover.Result
		var err error
		if r.Network.DiscoverContext != nil {
			result, err = r.Network.DiscoverContext(ctx, schedule.Runtime().Subnets, discoveryTimeout)
		} else {
			result, err = r.Network.Discover(schedule.Runtime().Subnets, discoveryTimeout)
		}
		if err != nil {
			r.failedf(ctx, "discovery failed: %v", err)
		} else {
			r.reportDiscovery(&out, result)
			r.rescue(observations, unresolved, result)
		}

		if skipped := schedule.CompletedDiscovery(now); skipped > 0 {
			r.logf("discovery is behind; skipped %d slot(s)", skipped)
		}
	}

	for _, target := range targets {
		if skipped := schedule.CompletedTarget(target, now); skipped > 0 {
			r.logf("target %d is behind its %ds interval; skipped %d slot(s)",
				target.ID, target.IntervalSeconds, skipped)
		}
	}

	// Recorded only once the round is settled: a sweep may still have found a target
	// that its own probe could not, and that counts as answering.
	for _, target := range targets {
		if observation := observations[target.ID]; observation != nil {
			schedule.RecordAnswer(target.ID, observation.Online)
		}
	}

	out.Observations = ordered(observations, targets)

	return out
}

// probeTargets pings every due target, following a device that moved where it can.
//
// Returns one observation per target, and the targets that answered nowhere at all.
func (r *Runner) probeTargets(targets []config.Target) (map[int64]*report.Observation, []config.Target) {
	return r.probeTargetsContext(context.Background(), targets)
}

func (r *Runner) probeTargetsContext(ctx context.Context, targets []config.Target) (map[int64]*report.Observation, []config.Target) {
	probe := func(hosts []net.IP, timeout time.Duration) ([]net.IP, error) {
		if r.Network.ProbeContext != nil {
			return r.Network.ProbeContext(ctx, hosts, timeout)
		}
		return r.Network.Probe(hosts, timeout)
	}
	observations := make(map[int64]*report.Observation, len(targets))

	if len(targets) == 0 {
		return observations, nil
	}

	known := make([]net.IP, 0, len(targets))
	for _, target := range targets {
		if ip := net.ParseIP(target.IP); ip != nil {
			known = append(known, ip)
		}
	}

	replied, err := probe(known, probeTimeout)

	// A target outside every attached network is unreachable from here, which is a
	// finding rather than a malfunction: it is reported like any other silent device,
	// so the sweep that follows can find it at a new address and say so. Treating it as
	// a broken probe would leave the agent unable to report anything about the devices
	// it *can* still reach.
	offLAN := errors.Is(err, discover.ErrOffLAN)
	if offLAN {
		err = nil
	}

	// Said once when it starts and once when it clears. It is a standing condition, not
	// an event: a device can sit on a network the agent has left for weeks, and a line
	// every probe interval would be thousands a day saying the same unchanged thing.
	if offLAN != r.offLAN {
		if offLAN {
			r.logf("some targets are no longer on any network this machine is attached to")
		} else {
			r.logf("every target is back on an attached network")
		}

		r.offLAN = offLAN
	}

	// Read after the probes, never before: a host that just answered is in the kernel's
	// table because of it, which is what lets the address be tied back to a device.
	table := index(r.Network.Neighbours())

	answered := map[string]bool{}

	switch {
	case err != nil:
		r.failedf(ctx, "probe failed: %v", err)
		// A send failure is not evidence of absence. The server watchdog handles
		// missing samples if probing remains unavailable. Keep positive evidence
		// from hosts whose packets were delivered even if other sends failed.
		for _, ip := range replied {
			answered[ip.String()] = true
		}
		for _, target := range targets {
			if answered[target.IP] && r.isTheSameDevice(target, table) {
				observations[target.ID] = &report.Observation{ID: target.ID, Online: true, IP: target.IP}
			}
		}
		return observations, nil
	default:
		for _, ip := range replied {
			answered[ip.String()] = true
		}
	}

	var moved []config.Target

	for _, target := range targets {
		if answered[target.IP] && r.isTheSameDevice(target, table) {
			observations[target.ID] = &report.Observation{ID: target.ID, Online: true, IP: target.IP}

			continue
		}

		observations[target.ID] = &report.Observation{ID: target.ID, Online: false}
		moved = append(moved, target)
	}

	// Nothing answered where it used to. Before calling any of it an outage, ask the
	// kernel whether it already knows those devices at a different address — something
	// else on the segment may well have talked to them since.
	candidates := make([]net.IP, 0, len(moved))
	elsewhere := make(map[int64]net.IP, len(moved))

	for _, target := range moved {
		if target.MAC == "" {
			continue
		}

		if ip, ok := table.whereIs(target.MAC); ok && ip.String() != target.IP {
			elsewhere[target.ID] = ip
			candidates = append(candidates, ip)
		}
	}

	if len(candidates) > 0 {
		// The cached address is only a candidate: DHCP may have reassigned it.
		// Read again after probing so the answer is tied to its current owner.
		found, err := probe(candidates, probeTimeout)
		if err != nil {
			r.failedf(ctx, "probe failed: %v", err)
		}

		reachable := map[string]bool{}
		for _, ip := range found {
			reachable[ip.String()] = true
		}

		fresh := index(r.Network.Neighbours())
		for _, target := range moved {
			id := target.ID
			ip, candidate := elsewhere[id]
			if !candidate {
				continue
			}
			if err != nil && !reachable[ip.String()] {
				delete(observations, id)
				continue
			}
			if mac, known := fresh.holder(ip.String()); reachable[ip.String()] && known && mac == discover.NormaliseMAC(target.MAC) {
				observations[id].Online = true
				observations[id].IP = ip.String()
			}
		}
	}

	var unresolved []config.Target
	for _, target := range moved {
		if observation := observations[target.ID]; observation != nil && !observation.Online {
			unresolved = append(unresolved, target)
		}
	}

	return observations, unresolved
}

// isTheSameDevice checks that the answer came from the device we meant to ask.
//
// An address is not an identity: a DHCP lease gets handed on, and the machine that
// picks it up next answers a probe exactly as the old one did. Reporting that as the
// monitored device being up is the worst error a monitor can make, because it hides a
// real outage. When the kernel can say who holds the address, it is asked; when it
// cannot, the answer is taken at face value rather than inventing an outage.
func (r *Runner) isTheSameDevice(target config.Target, table neighbours) bool {
	if target.MAC == "" {
		return true
	}

	mac, known := table.holder(target.IP)
	if !known {
		return true
	}

	if mac == discover.NormaliseMAC(target.MAC) {
		return true
	}

	r.logf("target %d: %s answered, but it is held by %s and not %s", target.ID, target.IP, mac, target.MAC)

	return false
}

// rescue upgrades a target that a sweep found alive at an address nobody expected.
//
// Without this the move would be reported as an outage first and a move only later,
// which means an incident the owner should never have been sent.
func (r *Runner) rescue(observations map[int64]*report.Observation, unresolved []config.Target, result discover.Result) {
	if len(unresolved) == 0 {
		return
	}

	byMAC := make(map[string]discover.Device, len(result.Devices))
	for _, device := range result.Devices {
		if device.MAC != "" {
			byMAC[discover.NormaliseMAC(device.MAC)] = device
		}
	}

	for _, target := range unresolved {
		if target.MAC == "" {
			continue
		}

		device, ok := byMAC[discover.NormaliseMAC(target.MAC)]
		if !ok {
			continue
		}

		observation := observations[target.ID]
		observation.Online = true
		observation.IP = device.IP
		observation.Hostname = device.Hostname

		r.logf("target %d answered at %s instead of %s", target.ID, device.IP, target.IP)
	}
}

// reportDiscovery attaches a sweep to the report.
func (r *Runner) reportDiscovery(out *report.Report, result discover.Result) {
	if result.Degraded {
		r.logf("active discovery unavailable; no presence inferred from cached neighbours")
	}

	for _, failure := range result.Failures {
		r.logf("discovery problem: %v", failure)
	}

	interfaces := make([]report.Interface, 0, len(result.Interfaces))
	for _, attachment := range result.Interfaces {
		interfaces = append(interfaces, report.Interface{Name: attachment.Name, CIDR: attachment.CIDR})
	}

	devices := make([]report.Device, 0, len(result.Devices))
	for _, device := range result.Devices {
		devices = append(devices, report.Device{
			MAC:      device.MAC,
			IP:       device.IP,
			Hostname: device.Hostname,
		})
	}

	scanned := append([]string(nil), result.Scanned...)
	if scanned == nil {
		scanned = []string{}
	}

	out.Interfaces = &interfaces
	out.Devices = &devices
	out.Scanned = &scanned
}

// prepare fills in whatever the caller left out.
func (r *Runner) prepare() {
	if r.Logger == nil {
		r.Logger = log.Default()
	}
	if r.Network.Discover == nil {
		r.Network.Discover = discover.Run
	}
	if r.Network.Probe == nil {
		r.Network.Probe = discover.ProbeLocal
	}
	if r.Network.Neighbours == nil {
		r.Network.Neighbours = discover.Neighbors
	}
	if r.Clock.Now == nil {
		r.Clock.Now = time.Now
	}
	if r.Backoff == nil {
		r.Backoff = defaultBackoff
	}
	if r.Phase == nil {
		r.Phase = PhaseFor
	}
}

// logf writes one line to wherever the runner logs.
func (r *Runner) logf(format string, arguments ...any) {
	r.Logger.Printf(format, arguments...)
}

// failedf reports a failure, unless the agent is being shut down.
//
// Cancelling the round closes the sockets under it, so a stop produces exactly the same
// errors as a broken network: "use of closed network connection" from a read that was
// still waiting. A service manager stops this process routinely — on every upgrade, every
// reboot, every configuration change — and each of those would otherwise leave a line
// behind saying the probe failed, for an operator to go looking into. Nothing failed; we
// asked it to stop.
func (r *Runner) failedf(ctx context.Context, format string, arguments ...any) {
	if ctx.Err() != nil {
		return
	}

	r.Logger.Printf(format, arguments...)
}

// debugf writes a line only when the operator asked for the detail.
func (r *Runner) debugf(format string, arguments ...any) {
	if !r.Verbose {
		return
	}

	r.Logger.Printf(format, arguments...)
}

// forget drops the remembered answers of targets the server no longer sends.
//
// The schedule prunes its own two maps on every configuration change; this is the third,
// and a process meant to run for a year without being looked at should not be the only
// one that quietly keeps everything it has ever seen.
func (r *Runner) forget(targets []config.Target) {
	if len(r.reported) == 0 {
		return
	}

	live := make(map[int64]struct{}, len(targets))
	for _, target := range targets {
		live[target.ID] = struct{}{}
	}

	for id := range r.reported {
		if _, ok := live[id]; !ok {
			delete(r.reported, id)
		}
	}
}

// noteAnswers records what every device answered and reports whether any of it changed.
//
// It has to be called on every round, because it is what "changed" is measured against.
//
// A change is a device seen for the first time, one that has gone quiet, or one that has
// come back. A device that is *still* down is not — the server already holds that
// incident, and on a fifteen second check a single unplugged printer would otherwise
// write nearly six thousand identical lines a day and bury everything that did change.
// --verbose is there for whoever wants the rounds in between.
func (r *Runner) noteAnswers(observations []report.Observation) bool {
	if r.reported == nil {
		r.reported = map[int64]bool{}
	}

	news := false

	for _, observation := range observations {
		previous, known := r.reported[observation.ID]
		if !known || previous != observation.Online {
			news = true
		}

		r.reported[observation.ID] = observation.Online
	}

	return news
}

// ordered turns the observation map back into the target order, so a report reads the
// same way twice.
func ordered(observations map[int64]*report.Observation, targets []config.Target) []report.Observation {
	if len(observations) == 0 {
		return nil
	}

	out := make([]report.Observation, 0, len(observations))

	for _, target := range targets {
		if observation, ok := observations[target.ID]; ok {
			out = append(out, *observation)
		}
	}

	return out
}

// discoveryState describes what happened to discovery, for the log line.
func discoveryState(round report.Report) string {
	if round.Devices == nil {
		return "skipped"
	}

	return "ran"
}

// defaultBackoff grows the wait after each consecutive failure and spreads the fleet
// out with jitter.
//
// Without the jitter every agent that lost the server at the same moment would come
// back at the same moment, and a fleet on a fifteen second interval is four times the
// stampede a sixty second one would be.
func defaultBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}

	delay := backoffBase << min(attempt-1, 16)
	if delay > backoffMax || delay <= 0 {
		delay = backoffMax
	}

	// Half the delay, plus up to half again.
	half := delay / 2

	return half + time.Duration(rand.Int63n(int64(half)+1))
}

// Tests may advance a virtual clock; live waits always respond to shutdown.
func (r *Runner) sleep(ctx context.Context, duration time.Duration) {
	if r.Clock.Sleep != nil {
		r.Clock.Sleep(duration)
		return
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
