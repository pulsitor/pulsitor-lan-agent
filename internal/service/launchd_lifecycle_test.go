package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchdStopStartLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.plist")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, running := false, false
	bootstraps := 0
	s := launchdService{path: path, label: "test", command: func(args ...string) ([]byte, error) {
		switch args[0] {
		case "bootstrap":
			if loaded || len(args) != 3 || args[1] != "system" || args[2] != path {
				t.Fatalf("bad bootstrap: %v", args)
			}
			loaded = true
			bootstraps++
		default:
			if len(args) != 2 || args[1] != "system/test" {
				t.Fatalf("wrong domain: %v", args)
			}
			switch args[0] {
			case "enable":
			case "print":
				if !loaded {
					return []byte("Could not find service"), errors.New("not loaded")
				}
				if running {
					return []byte("test = {\n\tstate = running\n}"), nil
				}
				return []byte("state = waiting"), nil
			case "kickstart":
				if !loaded {
					return nil, errors.New("not loaded")
				}
				running = true
			case "bootout":
				if !loaded {
					return nil, errors.New("not loaded")
				}
				loaded = false
				running = false
			default:
				t.Fatalf("unexpected command %v", args)
			}
		}
		return nil, nil
	}}
	for _, action := range []func() error{s.start, s.start, s.stop, s.stop, s.start} {
		if err := action(); err != nil {
			t.Fatal(err)
		}
	}
	status, err := s.query()
	if err != nil || !status.Running || !status.Installed || bootstraps != 2 {
		t.Fatalf("status=%+v error=%v bootstraps=%d", status, err, bootstraps)
	}
	if err := s.stop(); err != nil {
		t.Fatal(err)
	}
	status, err = s.query()
	if err != nil || status.Running || !status.Installed || status.Detail != "not loaded" {
		t.Fatalf("stopped status=%+v error=%v", status, err)
	}
}

func TestLaunchdLifecyclePropagatesFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.plist")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"enable", "bootstrap", "kickstart", "bootout"} {
		t.Run(command, func(t *testing.T) {
			failure := errors.New("permission denied")
			s := launchdService{path: path, label: "test", command: func(args ...string) ([]byte, error) {
				if args[0] == command {
					return nil, failure
				}
				if args[0] == "print" && command == "bootstrap" {
					return []byte("Could not find service"), errors.New("absent")
				}
				return nil, nil
			}}
			var err error
			if command == "bootout" {
				err = s.stop()
			} else {
				err = s.start()
			}
			if !errors.Is(err, failure) {
				t.Fatalf("lost %s error: %v", command, err)
			}
		})
	}
	s := launchdService{path: path, label: "test", command: func(...string) ([]byte, error) { return nil, errors.New("permission denied") }}
	if _, err := s.query(); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("query hid failure: %v", err)
	}
}
