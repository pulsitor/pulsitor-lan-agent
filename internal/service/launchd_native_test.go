//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in: exercises real launchd with an isolated job in the current GUI session.
// It neither installs nor starts the production agent and requires no root daemon.
func TestNativeLaunchdStopStart(t *testing.T) {
	if os.Getenv("PULSITOR_TEST_LAUNCHD") != "1" {
		t.Skip("set PULSITOR_TEST_LAUNCHD=1 in a macOS GUI session")
	}
	label := fmt.Sprintf("com.pulsitor.test.%d", os.Getpid())
	path := filepath.Join(t.TempDir(), label+".plist")
	contents := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>/bin/sleep</string><string>600</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>`, label)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	s := launchdService{path: path, label: label, domain: fmt.Sprintf("gui/%d", os.Getuid()), command: func(args ...string) ([]byte, error) {
		out, err := exec.Command("launchctl", args...).CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("launchctl %v: %w: %s", args, err, out)
		}
		return out, nil
	}}
	t.Cleanup(func() { _, _ = s.command("bootout", s.target()) })
	for round := 0; round < 2; round++ {
		if err := s.start(); err != nil {
			t.Fatal(err)
		}
		if err := s.start(); err != nil {
			t.Fatalf("repeated start: %v", err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			status, err := s.query()
			if err != nil {
				t.Fatal(err)
			}
			if status.Running {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("job did not start: %+v", status)
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err := s.stop(); err != nil {
			t.Fatal(err)
		}
		if err := s.stop(); err != nil {
			t.Fatalf("repeated stop: %v", err)
		}
		status, err := s.query()
		if err != nil || status.Running || !status.Installed {
			t.Fatalf("after stop: %+v / %v", status, err)
		}
	}
}
