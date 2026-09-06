//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// plistPath is where a system-wide daemon belongs. LaunchAgents would tie the agent to
// a logged-in user, which is exactly the lifetime a monitoring agent must not have.
const plistPath = "/Library/LaunchDaemons/" + Label + ".plist"

// Install writes the launchd job and loads it.
func Install(config Config) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("installing a service needs root; re-run under sudo")
	}

	contents, err := plist(config)
	if err != nil {
		return err
	}

	// launchd opens StandardErrorPath itself and will not create the directory to do
	// it, and the agent's own log sink is opened after the process has already started.
	if config.LogPath != "" {
		if err := os.MkdirAll(filepath.Dir(config.LogPath), 0o755); err != nil {
			return err
		}
	}

	// launchd refuses to load a plist that anyone but root can write.
	if err := writeFile(plistPath, contents, 0o644); err != nil {
		return err
	}

	if err := os.Chown(plistPath, 0, 0); err != nil {
		return err
	}

	return launchdManager().start()
}

// Uninstall unloads the job and removes it.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("removing a service needs root; re-run under sudo")
	}

	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		return ErrNotInstalled
	}

	if err := run("launchctl", "bootout", "system/"+Label); err != nil {
		_ = run("launchctl", "unload", "-w", plistPath)
	}

	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// launchdManager always addresses the system domain, including status queries made
// by an operator in an interactive login session.
func launchdManager() launchdService {
	return launchdService{path: plistPath, label: Label, command: func(arguments ...string) ([]byte, error) {
		output, err := exec.Command("launchctl", arguments...).CombinedOutput()
		if err != nil {
			return output, fmt.Errorf("launchctl %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
		}
		return output, nil
	}}
}

func Start() error           { return launchdManager().start() }
func Stop() error            { return launchdManager().stop() }
func Query() (Status, error) { return launchdManager().query() }

// DefaultStateDir is where the identity lives on this platform.
func DefaultStateDir() string {
	return "/Library/Application Support/Pulsitor/LANAgent"
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
