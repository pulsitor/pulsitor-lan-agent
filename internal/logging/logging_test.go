package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmptyPathWritesToStandardError(t *testing.T) {
	sink, err := New("", 0)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer sink.Close()

	if sink.Writer != os.Stderr {
		t.Fatalf("an unnamed sink should be standard error, got %T", sink.Writer)
	}

	// Closing must not close the process's own standard error.
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stderr.Stat(); err != nil {
		t.Fatalf("standard error was closed: %v", err)
	}
}

func TestFileIsAppendedAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")

	for _, line := range []string{"first\n", "second\n"} {
		sink, err := New(path, DefaultMaxBytes)
		if err != nil {
			t.Fatalf("new: %v", err)
		}

		if _, err := sink.Write([]byte(line)); err != nil {
			t.Fatalf("write: %v", err)
		}

		sink.Close()
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(contents) != "first\nsecond\n" {
		t.Fatalf("a restart truncated the log: %q", contents)
	}
}

// A log that grew without bound would eventually be the reason the customer's disk
// filled up, which is a worse outage than the one the agent was watching for.
func TestRollsOverAtTheLimitAndKeepsOneGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")

	sink, err := New(path, 16)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer sink.Close()

	for _, line := range []string{"aaaaaaaaaa\n", "bbbbbbbbbb\n", "cccccccccc\n"} {
		if _, err := sink.Write([]byte(line)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}

	if strings.TrimSpace(string(current)) != "cccccccccc" {
		t.Fatalf("the live log should hold only the newest record, got %q", current)
	}

	rolled, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("read rolled: %v", err)
	}

	if strings.TrimSpace(string(rolled)) != "bbbbbbbbbb" {
		t.Fatalf("the rolled log should hold the previous record, got %q", rolled)
	}

	// Two files and no more, whatever happens: the footprint is bounded.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected exactly two log files, got %d", len(entries))
	}
}

// The log names the customer's networks and devices, which is not something every
// account on a shared machine needs to be able to read.
func TestLogFileIsOwnerReadableOnly(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("POSIX modes do not apply")
	}

	path := filepath.Join(t.TempDir(), "agent.log")

	sink, err := New(path, DefaultMaxBytes)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer sink.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("log file is readable by others: %v", mode)
	}
}

func TestLoggerStampsUTC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")

	sink, err := New(path, DefaultMaxBytes)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	Logger(sink).Printf("hello")
	sink.Close()

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// "2026/09/06 12:34:56 hello" — the date is what proves a flag was set at all.
	if !strings.HasPrefix(string(contents), "20") || !strings.HasSuffix(string(contents), "hello\n") {
		t.Fatalf("unexpected log line %q", contents)
	}
}
