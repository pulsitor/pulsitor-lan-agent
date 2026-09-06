// Package config holds the agent's identity and the settings the server hands back.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"github.com/pulsitor/pulsitor-lan-agent/internal/discover"
	"github.com/pulsitor/pulsitor-lan-agent/internal/service"
)

// Identity is what the agent proves itself with. It is written once, at enrollment,
// and is the only secret the agent ever holds.
type Identity struct {
	Code   string `json:"agent_code"`
	Secret string `json:"agent_secret"`
}

// Target is one device the server wants probed, and how often.
//
// The interval belongs to the monitoring the owner configured, so two devices on the
// same network can be watched every fifteen seconds and once an hour respectively
// without either of them dragging the other along.
type Target struct {
	ID              int64  `json:"id"`
	IP              string `json:"ip"`
	MAC             string `json:"mac,omitempty"`
	IntervalSeconds int    `json:"interval_seconds"`
}

// Runtime is the configuration the server returns with every report. The agent keeps no
// opinion of its own: an empty Subnets means discover nothing, and an empty Targets
// means probe nothing.
type Runtime struct {
	// DiscoveryIntervalSeconds paces the full subnet sweep that fills the inventory.
	// It is deliberately unrelated to any monitoring's interval: finding devices
	// nobody has picked yet is not urgent work.
	DiscoveryIntervalSeconds int `json:"discovery_interval_seconds"`

	// DiscoveryMinIntervalSeconds is the floor for the extra sweep the agent runs when
	// a monitored device stops answering at its known address. Without it a device
	// that is genuinely gone would trigger a subnet scan on every probe.
	DiscoveryMinIntervalSeconds int `json:"discovery_min_interval_seconds"`

	// CheckInIntervalSeconds is the longest the agent may go without speaking to the
	// server at all. An agent whose only device is checked once an hour would
	// otherwise be silent for an hour: it would look dead, and it would take that long
	// to hear that anything about its schedule had changed.
	CheckInIntervalSeconds int `json:"check_in_interval_seconds"`

	Subnets []string `json:"subnets"`
	Targets []Target `json:"targets"`
}

// Equal reports whether two configurations say the same thing.
//
// Compared by value rather than by pointer: every report allocates a fresh Runtime, so
// a pointer comparison would rewrite the state file after every single one.
func (r *Runtime) Equal(other *Runtime) bool {
	if r == nil || other == nil {
		return r == other
	}

	if r.DiscoveryIntervalSeconds != other.DiscoveryIntervalSeconds ||
		r.DiscoveryMinIntervalSeconds != other.DiscoveryMinIntervalSeconds ||
		r.CheckInIntervalSeconds != other.CheckInIntervalSeconds ||
		len(r.Subnets) != len(other.Subnets) ||
		len(r.Targets) != len(other.Targets) {
		return false
	}

	for index := range r.Subnets {
		if r.Subnets[index] != other.Subnets[index] {
			return false
		}
	}

	for index := range r.Targets {
		if r.Targets[index] != other.Targets[index] {
			return false
		}
	}

	return true
}

// State is everything the agent keeps between runs.
//
// The runtime configuration is stored alongside the identity on purpose: without it a
// restart would probe nothing on its first pass, because the target list only arrives
// in the response to a report that has already been sent.
type State struct {
	Server   string    `json:"server,omitempty"`
	Identity *Identity `json:"identity"`
	Runtime  *Runtime  `json:"runtime,omitempty"`
}

// Load reads the stored state. A missing file is not an error — it means the agent has
// not enrolled yet.
func Load(path string) (*State, error) {
	if err := protectExistingState(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}

	state := &State{}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, fmt.Errorf("state file %s is not readable: %w", path, err)
	}

	if state.Identity == nil || state.Identity.Code == "" || state.Identity.Secret == "" {
		return nil, fmt.Errorf("state file %s holds no usable identity", path)
	}

	if state.Runtime != nil {
		if err := state.Runtime.Validate(); err != nil {
			return nil, err
		}
	}
	return state, nil
}

// Save writes the state with owner-only permissions; it holds a bearer credential for
// everything the agent may report.
func Save(path string, state *State) error {
	if err := prepareStateDirectory(filepath.Dir(path)); err != nil {
		return err
	}

	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	// Write beside the destination so rename stays on the same filesystem. A
	// failed write leaves the previous identity intact, and readers see whole JSON.
	file, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()

	if err := protectStateFile(file.Name()); err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}

	// Persist the directory entry as well as the file contents on Unix.
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	}
	return nil
}

// EnsureWritable checks that an identity could be stored at a path, before anything
// irreversible is done to obtain one.
//
// An enrollment token is good exactly once. Redeeming it and only then finding that the
// state file cannot be written spends the customer's token on nothing, leaves no
// identity behind and gives them no way to retry — they have to work out for themselves
// that they need a fresh token. Everything about that is avoidable by asking the
// filesystem first.
func EnsureWritable(path string) error {
	directory := filepath.Dir(path)

	if err := prepareStateDirectory(directory); err != nil {
		return fmt.Errorf("%s: %w%s", directory, err, advice(err))
	}

	// Permission to create the directory is not permission to write in it, and an
	// existing directory says nothing at all — so the check is an actual write.
	probe, err := os.CreateTemp(directory, ".writable-*")
	if err != nil {
		return fmt.Errorf("%s is not writable: %w%s", directory, err, advice(err))
	}

	name := probe.Name()
	_ = probe.Close()

	return os.Remove(name)
}

// advice turns a permission error into the sentence that resolves it. The agent stores
// its identity in a system directory, so an unprivileged run lands here first, and
// "permission denied" on its own leaves the operator guessing which of the two fixes
// they want.
func advice(err error) string {
	if !errors.Is(err, os.ErrPermission) {
		return ""
	}

	return " (run this under sudo, or pass --state with a path you can write)"
}

// Validate before persisting or applying untrusted server configuration.
func (r *Runtime) Validate() error {
	for _, seconds := range []int{r.DiscoveryIntervalSeconds, r.DiscoveryMinIntervalSeconds, r.CheckInIntervalSeconds} {
		if seconds < 0 || seconds > 86400 {
			return fmt.Errorf("configuration interval is outside 0..86400 seconds")
		}
	}
	if len(r.Subnets) > 32 || len(r.Targets) > 512 {
		return fmt.Errorf("configuration exceeds protocol limits")
	}
	subnets := map[string]bool{}
	for _, cidr := range r.Subnets {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil || ip.To4() == nil || !discover.IsPrivate(ip) || network.String() != cidr {
			return fmt.Errorf("invalid discovery subnet %q", cidr)
		}
		if _, err := discover.Hosts(network); err != nil {
			return err
		}
		if subnets[cidr] {
			return fmt.Errorf("duplicate subnet %q", cidr)
		}
		subnets[cidr] = true
	}
	ids := map[int64]bool{}
	for _, target := range r.Targets {
		ip := net.ParseIP(target.IP)
		if target.ID <= 0 || ids[target.ID] || ip.To4() == nil || !discover.IsPrivate(ip) || target.IntervalSeconds < 1 || target.IntervalSeconds > 86400 {
			return fmt.Errorf("invalid monitoring target %d", target.ID)
		}
		if target.MAC != "" && discover.NormaliseMAC(target.MAC) == "" {
			return fmt.Errorf("invalid MAC for target %d", target.ID)
		}
		ids[target.ID] = true
	}
	return nil
}

// DefaultStatePath is where the identity lives when nobody named a path.
//
// It is the service package's directory rather than one of its own, because the two
// must not be able to disagree: an agent enrolled at one path and started as a service
// reading another would re-enroll on every boot and leave a trail of dead agents behind
// it in the customer's account.
func DefaultStatePath() string {
	return filepath.Join(service.DefaultStateDir(), "identity.json")
}
