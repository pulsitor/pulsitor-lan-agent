// Package service registers the agent with whatever supervises long-running processes
// on the machine it was installed on.
//
// The agent is a daemon: it has to come back after a reboot, after a crash and after
// the operator logs out, and on none of the three platforms does simply starting the
// binary achieve that. systemd, launchd and the Windows service manager each want the
// same three things — a unit description, an install step, and a process that responds
// when it is told to stop — and this package is that translation, one file per
// platform, so the rest of the agent never learns which one it is running under.
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Name is what the service is called on every platform that permits it. Windows shows
// DisplayName in services.msc; the short name is what `sc` and `systemctl` take.
const (
	Name        = "pulsitor-lan-agent"
	DisplayName = "Pulsitor LAN agent"
	Description = "Reports the devices on this network to Pulsitor."
)

// ErrUnsupported says this platform has no service manager the agent knows how to talk
// to. The agent still runs in the foreground; only installation is unavailable.
var ErrUnsupported = errors.New("installing a service is not supported on this platform")

// ErrNotInstalled says there is nothing to act on.
var ErrNotInstalled = errors.New("the service is not installed")

// Config is everything the service manager needs to start the agent again without us.
//
// The arguments are stored in the unit rather than read from a file at startup, because
// a service that depends on a second file to know what to do is a service that fails in
// a way nobody can see. The one thing deliberately never stored here is the enrollment
// token: installation redeems it for an identity first, and the identity lives in the
// state file with its own permissions.
type Config struct {
	Executable string
	Arguments  []string
	LogPath    string
}

// Status is what the service manager says about the service right now.
type Status struct {
	Installed bool
	Running   bool

	// Detail is the platform's own wording, which is what an operator will search for.
	Detail string
}

// String renders a status for the operator.
func (s Status) String() string {
	switch {
	case !s.Installed:
		return "not installed"
	case s.Running:
		return "running" + detail(s.Detail)
	default:
		return "installed but not running" + detail(s.Detail)
	}
}

func detail(value string) string {
	if value == "" {
		return ""
	}

	return " (" + value + ")"
}

// DefaultLogPath is where a service writes when nobody gave it a path.
//
// Linux is empty on purpose: a systemd unit's standard error goes to the journal, which
// is where an operator on that platform already looks, and a second copy in a file
// nobody rotates is a liability rather than a convenience.
func DefaultLogPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(programData(), "Pulsitor", "LANAgent", "agent.log")
	case "darwin":
		return "/Library/Logs/Pulsitor/lan-agent.log"
	default:
		return ""
	}
}

// programData is where Windows keeps machine-wide application state.
func programData() string {
	if path := os.Getenv("ProgramData"); path != "" {
		return path
	}

	return `C:\ProgramData`
}

// Executable is the absolute path of the running binary, which is what the service
// manager has to be given: a relative path would resolve against the service manager's
// working directory rather than the operator's.
func Executable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return filepath.Abs(path)
	}

	return filepath.Abs(resolved)
}

// commandLine renders an executable and its arguments as one quoted string, for the
// service definitions that take a command rather than a list.
func commandLine(executable string, arguments []string) string {
	parts := make([]string, 0, len(arguments)+1)

	for _, part := range append([]string{executable}, arguments...) {
		parts = append(parts, quote(part))
	}

	return strings.Join(parts, " ")
}

// quote wraps an argument only when it would otherwise be read as several.
func quote(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\"'\\") {
		return value
	}

	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

// writeFile writes a service definition, replacing whatever was there before.
func writeFile(path, contents string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("%s: %w", filepath.Dir(path), err)
	}

	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	return nil
}

// DefaultInstallPath is where the binary belongs once it is a service.
//
// A service started from wherever the operator happened to download it is a service
// that stops working the day somebody tidies their Downloads folder, so installation
// puts the binary somewhere it is meant to stay and points the unit at that.
func DefaultInstallPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(programFiles(), "Pulsitor", "LAN Agent", Name+".exe")
	}

	return "/usr/local/bin/" + Name
}

// programFiles is where Windows keeps installed software.
func programFiles() string {
	if path := os.Getenv("ProgramFiles"); path != "" {
		return path
	}

	return `C:\Program Files`
}

// InstallBinary copies the running binary to its permanent home, and reports the path
// the service should be pointed at.
//
// Copied rather than moved: the operator ran this binary, and a command that deletes
// the file it was invoked from is a surprise nobody wants from an installer.
func InstallBinary(source, destination string) (string, error) {
	if source == destination {
		return destination, nil
	}

	if same, err := sameFile(source, destination); err == nil && same {
		return destination, nil
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return "", fmt.Errorf("%s: %w", filepath.Dir(destination), err)
	}

	contents, err := os.ReadFile(source)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", source, err)
	}

	// Written beside the destination and renamed, so an interrupted copy cannot leave
	// a half-written binary that the service manager will faithfully try to execute.
	temporary, err := os.CreateTemp(filepath.Dir(destination), "."+Name+"-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(temporary.Name())

	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()

		return "", err
	}

	if err := temporary.Close(); err != nil {
		return "", err
	}

	if err := os.Chmod(temporary.Name(), 0o755); err != nil {
		return "", err
	}

	// Windows refuses to replace a file that is open, which is exactly what an upgrade
	// over a running service is; the caller stops it first, and this makes the failure
	// legible when it does not.
	if err := os.Rename(temporary.Name(), destination); err != nil {
		return "", fmt.Errorf("installing to %s (stop the service first if it is running): %w", destination, err)
	}

	return destination, nil
}

// sameFile reports whether two paths are the same file on disk.
func sameFile(left, right string) (bool, error) {
	first, err := os.Stat(left)
	if err != nil {
		return false, err
	}

	second, err := os.Stat(right)
	if err != nil {
		return false, err
	}

	return os.SameFile(first, second), nil
}
