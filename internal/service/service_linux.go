//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// unitPath is where a unit an administrator installed belongs — not /lib or /usr/lib,
// which are the package manager's.
const unitPath = "/etc/systemd/system/" + Name + ".service"

// Install writes the systemd unit and starts it.
func Install(config Config) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("installing a service needs root; re-run under sudo")
	}

	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("%w: no systemctl on this machine", ErrUnsupported)
	}

	// Best effort: an unprivileged account is better, but a machine whose user tools
	// are missing or locked down should still end up with a working agent.
	owner := ensureAccount()

	if err := prepareState(config, owner); err != nil {
		return err
	}

	if err := writeFile(unitPath, systemdUnit(config, owner, DefaultStateDir()), 0o644); err != nil {
		return err
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}

	return run("systemctl", "enable", "--now", Name)
}

// Uninstall stops the unit and removes it.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("removing a service needs root; re-run under sudo")
	}

	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return ErrNotInstalled
	}

	// Neither is fatal: a unit that was already stopped, or was never enabled, must
	// still be removable.
	_ = run("systemctl", "disable", "--now", Name)

	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return run("systemctl", "daemon-reload")
}

// Start starts the installed unit.
func Start() error {
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return ErrNotInstalled
	}

	return run("systemctl", "start", Name)
}

// Stop stops the installed unit.
func Stop() error {
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return ErrNotInstalled
	}

	return run("systemctl", "stop", Name)
}

// Query asks systemd what state the unit is in.
func Query() (Status, error) {
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return Status{}, nil
	}

	// `is-active` exits non-zero for every state but "active", so the output is what
	// carries the answer and the exit code is not an error.
	output, _ := exec.Command("systemctl", "is-active", Name).Output()
	state := strings.TrimSpace(string(output))

	return Status{Installed: true, Running: state == "active", Detail: state}, nil
}

// prepareState makes the identity readable by the account the unit will run as. The
// enrollment happened as root a moment ago, so without this the service starts and
// cannot read the identity it was just given.
//
// It also creates the log directory when one was named. ProtectSystem=strict refuses to
// start a unit whose ReadWritePaths names a path that does not exist, so a --log-file in
// a fresh directory would otherwise produce a service that never runs at all and an
// error message about mount namespaces that says nothing about logs.
func prepareState(config Config, owner string) error {
	directory := filepath.Dir(statePathFrom(config, DefaultStateDir()))

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}

	if config.LogPath != "" {
		if err := os.MkdirAll(filepath.Dir(config.LogPath), 0o750); err != nil {
			return err
		}
	}

	if owner == "" {
		return nil
	}

	account, err := user.Lookup(owner)
	if err != nil {
		return nil
	}

	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return nil
	}

	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		gid = uid
	}

	_ = os.Chown(directory, uid, gid)

	if config.LogPath != "" {
		_ = os.Chown(filepath.Dir(config.LogPath), uid, gid)
		_ = os.Chown(config.LogPath, uid, gid)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		_ = os.Chown(filepath.Join(directory, entry.Name()), uid, gid)
	}

	return nil
}

// ensureAccount returns the unprivileged account to run as, creating it if it is
// missing. An empty result means the unit has to run as root.
func ensureAccount() string {
	if _, err := user.Lookup(account); err == nil {
		return account
	}

	// The account's home is the state directory, so a tool that resolves ~ for it
	// lands somewhere that exists rather than in /var/lib itself.
	directory := DefaultStateDir()

	// Distributions disagree on which of these exists, and on what its flags are
	// called; whichever answers first is used.
	attempts := [][]string{
		{"useradd", "--system", "--no-create-home", "--home-dir", directory, "--shell", "/usr/sbin/nologin", account},
		{"useradd", "-r", "-M", "-d", directory, "-s", "/bin/false", account},
		{"adduser", "--system", "--no-create-home", "--group", "--home", directory, account},
	}

	for _, attempt := range attempts {
		if _, err := exec.LookPath(attempt[0]); err != nil {
			continue
		}

		if err := exec.Command(attempt[0], attempt[1:]...).Run(); err == nil {
			if _, err := user.Lookup(account); err == nil {
				return account
			}
		}
	}

	return ""
}

// DefaultStateDir is where the identity lives on this platform.
func DefaultStateDir() string {
	return "/var/lib/" + Name
}

// run executes one command, surfacing whatever it complained about.
func run(name string, arguments ...string) error {
	output, err := exec.Command(name, arguments...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(arguments, " "), err)
		}

		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(arguments, " "), err, message)
	}

	return nil
}
