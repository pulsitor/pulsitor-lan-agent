// Package agent runs the agent's work: what to do, when, and what to report about it.
package agent

import (
	"hash/fnv"
	"slices"
	"time"

	"github.com/pulsitor/pulsitor-lan-agent/internal/config"
)

// Floors the agent applies to whatever the server sends. The server has its own, lower
// bounds; these only stop a malformed configuration from turning into a tight loop.
const (
	minTargetInterval    = 5 * time.Second
	minDiscoveryInterval = 30 * time.Second
	minCheckInInterval   = 15 * time.Second
)

// Schedule tracks when each piece of work is next due.
//
// Every deadline is advanced from the time it was *due*, never from the time the work
// finished. Sleeping for the interval after each round would make the real period
// "interval plus however long the round took", which at fifteen seconds is a drift of a
// quarter and would walk every sample steadily towards the server's deadline.
type Schedule struct {
	runtime *config.Runtime

	// phase spreads this agent's grid away from every other agent's. Without it the
	// whole fleet would align to the same absolute instants and arrive together.
	phase time.Duration

	discoveryDueAt  time.Time
	lastDiscoveryAt time.Time
	checkInDueAt    time.Time
	targetDueAt     map[int64]time.Time

	// answering remembers whether each target's last probe succeeded. A device only
	// moves once, so an extra sweep is worth asking for when one has *just* gone
	// quiet — not every minute for a device that has been gone for a week.
	answering map[int64]bool
}

// New builds a schedule in which everything is due at once: a freshly started agent
// has no idea how long it has been away, so it reports before it waits.
func New(runtime *config.Runtime, now time.Time, phase time.Duration) *Schedule {
	schedule := &Schedule{
		runtime:        runtime,
		phase:          phase,
		discoveryDueAt: now,
		checkInDueAt:   now,
		targetDueAt:    map[int64]time.Time{},
		answering:      map[int64]bool{},
	}

	schedule.Apply(runtime, now)

	return schedule
}

// Runtime is the configuration currently in force.
func (s *Schedule) Runtime() *config.Runtime {
	return s.runtime
}

// Apply takes on a configuration the server just sent.
//
// A target that has just appeared is due immediately — the owner turned a monitoring on
// and should not wait an interval for its first sample. A target that has gone is
// forgotten, so a monitoring switched off stops costing packets at once.
func (s *Schedule) Apply(runtime *config.Runtime, now time.Time) {
	previous := s.runtime
	if previous != nil && !slices.Equal(previous.Subnets, runtime.Subnets) {
		s.discoveryDueAt = now
	}
	oldTargets := map[int64]config.Target{}
	if previous != nil {
		for _, target := range previous.Targets {
			oldTargets[target.ID] = target
		}
	}
	s.runtime = runtime

	if s.targetDueAt == nil {
		s.targetDueAt = map[int64]time.Time{}
	}
	if s.answering == nil {
		s.answering = map[int64]bool{}
	}

	live := make(map[int64]struct{}, len(runtime.Targets))

	for _, target := range runtime.Targets {
		live[target.ID] = struct{}{}

		if _, known := s.targetDueAt[target.ID]; !known || oldTargets[target.ID] != target {
			s.targetDueAt[target.ID] = now
		}
	}

	for id := range s.targetDueAt {
		if _, ok := live[id]; !ok {
			delete(s.targetDueAt, id)
			delete(s.answering, id)
		}
	}
}

// WasAnswering reports whether this target's previous probe succeeded. A target never
// probed before counts as answering, so its first failure is still treated as a device
// that may have moved rather than one that was never there.
func (s *Schedule) WasAnswering(id int64) bool {
	answering, known := s.answering[id]

	return !known || answering
}

// RecordAnswer notes how a target's probe went.
func (s *Schedule) RecordAnswer(id int64, answered bool) {
	s.answering[id] = answered
}

// Reconcile pulls back any deadline that has drifted further away than its own
// interval, and reports whether it had to.
//
// Probe slots sit on the wall clock so that devices sharing an interval batch together,
// which makes them sensitive to a clock that steps backwards — an NTP correction on a
// machine with no battery-backed clock, which is exactly the kind these agents run on.
// Without this the whole schedule would sit in the far future and the agent would stay
// silent until real time caught up with it, long enough for the server to call every
// one of its devices dead.
//
// It does the same job for a shortened interval. A device moved from hourly to fifteen
// seconds already holds a slot an hour away, and the server starts expecting it every
// fifteen seconds the moment the owner saves — so without pulling that slot back, the
// change would raise an outage for a device that is perfectly fine.
func (s *Schedule) Reconcile(now time.Time) bool {
	rebased := false

	clamp := func(due time.Time, interval time.Duration) time.Time {
		if due.Sub(now) <= interval {
			return due
		}

		rebased = true

		return now.Add(interval)
	}

	s.discoveryDueAt = clamp(s.discoveryDueAt, s.discoveryInterval(s.runtime.DiscoveryIntervalSeconds, minDiscoveryInterval))
	s.checkInDueAt = clamp(s.checkInDueAt, s.discoveryInterval(s.runtime.CheckInIntervalSeconds, minCheckInInterval))

	for _, target := range s.runtime.Targets {
		if due, ok := s.targetDueAt[target.ID]; ok {
			s.targetDueAt[target.ID] = clamp(due, targetInterval(target))
		}
	}

	// A sweep can only have happened in the past.
	if s.lastDiscoveryAt.After(now) {
		s.lastDiscoveryAt = now
		rebased = true
	}

	return rebased
}

// Due reports what has to happen now.
func (s *Schedule) Due(now time.Time) (bool, []config.Target) {
	discovery := !s.discoveryDueAt.After(now)

	targets := make([]config.Target, 0, len(s.runtime.Targets))

	for _, target := range s.runtime.Targets {
		if due, ok := s.targetDueAt[target.ID]; ok && !due.After(now) {
			targets = append(targets, target)
		}
	}

	return discovery, targets
}

// TargetDueAt is when one target is next expected to be probed.
func (s *Schedule) TargetDueAt(id int64) time.Time {
	return s.targetDueAt[id]
}

// CheckInDue reports whether the agent owes the server a word regardless of whether it
// has any work to show for it.
func (s *Schedule) CheckInDue(now time.Time) bool {
	return !s.checkInDueAt.After(now)
}

// CompletedCheckIn notes that the server has just heard from us. Every report counts,
// whatever prompted it.
func (s *Schedule) CompletedCheckIn(now time.Time) {
	s.checkInDueAt = now.Add(s.discoveryInterval(s.runtime.CheckInIntervalSeconds, minCheckInInterval))
}

// Wait is how long to sleep before anything is due again.
func (s *Schedule) Wait(now time.Time) time.Duration {
	earliest := s.discoveryDueAt

	if s.checkInDueAt.Before(earliest) {
		earliest = s.checkInDueAt
	}

	for _, target := range s.runtime.Targets {
		if due, ok := s.targetDueAt[target.ID]; ok && due.Before(earliest) {
			earliest = due
		}
	}

	if wait := earliest.Sub(now); wait > 0 {
		return wait
	}

	return 0
}

// MayDiscover reports whether an unscheduled sweep is allowed yet.
//
// A monitored device that stops answering at its known address may have moved, and a
// sweep is how the agent finds out. Doing that on every failed probe would mean a
// device that is genuinely gone triggers a subnet scan every interval, so it is held to
// a floor of its own.
func (s *Schedule) MayDiscover(now time.Time) bool {
	if s.lastDiscoveryAt.IsZero() {
		return true
	}

	return !now.Before(s.lastDiscoveryAt.Add(s.discoveryInterval(s.runtime.DiscoveryMinIntervalSeconds, minDiscoveryInterval)))
}

// CompletedDiscovery moves discovery on to its next slot.
func (s *Schedule) CompletedDiscovery(now time.Time) (skipped int) {
	s.lastDiscoveryAt = now

	interval := s.discoveryInterval(s.runtime.DiscoveryIntervalSeconds, minDiscoveryInterval)

	s.discoveryDueAt, skipped = advance(s.discoveryDueAt, interval, now)

	return skipped
}

// CompletedTarget moves one target on to its next slot.
//
// Slots sit on a fixed grid rather than an interval after the last probe, so that every
// device sharing an interval falls due in the same round and leaves in one request. A
// per-target phase would mean an agent watching fifty devices on a sixty second check
// sending fifty reports a minute instead of one — enough to trip its own rate limit and
// lose the monitoring altogether.
//
// It also means a backlog can never build up: however far behind the agent has fallen,
// the grid offers exactly one pending slot, never a burst of them describing moments
// that have already gone.
func (s *Schedule) CompletedTarget(target config.Target, now time.Time) (skipped int) {
	interval := targetInterval(target)

	next := s.slot(interval, now)

	if planned, ok := s.targetDueAt[target.ID]; ok {
		if gap := next.Sub(planned); gap > interval {
			skipped = int(gap/interval) - 1
		}
	}

	s.targetDueAt[target.ID] = next

	return skipped
}

// slot is the next instant on this agent's grid for a given interval.
func (s *Schedule) slot(interval time.Duration, now time.Time) time.Time {
	if interval <= 0 {
		interval = minTargetInterval
	}

	offset := s.phase % interval

	next := now.Add(-offset).Truncate(interval).Add(interval + offset)

	// Truncate rounds down, so landing exactly on a slot would otherwise return the
	// instant we are already at and fire again with no wait.
	if !next.After(now) {
		next = next.Add(interval)
	}

	return next
}

// targetInterval is a target's interval, held at a floor so a malformed configuration
// cannot turn the loop into a spin.
func targetInterval(target config.Target) time.Duration {
	interval := time.Duration(target.IntervalSeconds) * time.Second
	if interval < minTargetInterval {
		return minTargetInterval
	}

	return interval
}

// PhaseFor derives a stable, evenly spread offset from the agent's identity, so that
// two agents on the same interval do not report in the same instant.
func PhaseFor(code string) time.Duration {
	digest := fnv.New32a()
	_, _ = digest.Write([]byte(code))

	return time.Duration(digest.Sum32()%3600) * time.Second
}

// discoveryInterval reads a configured interval, holding it at a sane floor.
func (s *Schedule) discoveryInterval(seconds int, floor time.Duration) time.Duration {
	interval := time.Duration(seconds) * time.Second
	if interval < floor {
		return floor
	}

	return interval
}

// advance returns the next deadline after a slot has been served, keeping the original
// phase.
//
// When the agent has fallen so far behind that the next slot is already past, whole
// intervals are skipped rather than served back to back: catching up would mean a burst
// of probes and a burst of samples, all of them describing a moment that has gone.
func advance(planned time.Time, interval time.Duration, now time.Time) (time.Time, int) {
	// Run ahead of its slot — an extra sweep asked for by a device that just went
	// quiet. The clock restarts from the work rather than from the slot it skipped,
	// otherwise one early sweep would push the scheduled one a whole interval away.
	if planned.After(now) {
		return now.Add(interval), 0
	}

	next := planned.Add(interval)
	if next.After(now) {
		return next, 0
	}

	missed := int(now.Sub(planned) / interval)

	return planned.Add(time.Duration(missed+1) * interval), missed
}
