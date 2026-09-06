package service

import (
	"os"
	"path/filepath"
	"testing"
)

// A customer's install path can hold a space — "Program Files" and "Application
// Support" both do — and a command line that does not say so becomes two arguments.
func TestCommandLineQuotesWhatWouldSplit(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		executable string
		arguments  []string
		want       string
	}{
		{
			name:       "nothing to quote",
			executable: "/usr/local/bin/pulsitor-lan-agent",
			arguments:  []string{"--server", "https://x.example"},
			want:       `/usr/local/bin/pulsitor-lan-agent --server https://x.example`,
		},
		{
			name:       "spaces in the path",
			executable: `C:\Program Files\Pulsitor\LAN Agent\agent.exe`,
			arguments:  []string{"--state", `C:\ProgramData\Pulsitor\identity.json`},
			want:       `"C:\Program Files\Pulsitor\LAN Agent\agent.exe" --state "C:\ProgramData\Pulsitor\identity.json"`,
		},
		{
			name:       "empty argument",
			executable: "/bin/agent",
			arguments:  []string{""},
			want:       `/bin/agent ""`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := commandLine(testCase.executable, testCase.arguments); got != testCase.want {
				t.Fatalf("got  %s\nwant %s", got, testCase.want)
			}
		})
	}
}

func TestQuoteEscapesEmbeddedQuotes(t *testing.T) {
	if got := quote(`a"b`); got != `"a\"b"` {
		t.Fatalf("quote(`a\"b`) = %s", got)
	}
}

func TestStatusReads(t *testing.T) {
	for _, testCase := range []struct {
		status Status
		want   string
	}{
		{Status{}, "not installed"},
		{Status{Installed: true, Detail: "inactive"}, "installed but not running (inactive)"},
		{Status{Installed: true, Running: true, Detail: "active"}, "running (active)"},
		{Status{Installed: true, Running: true}, "running"},
	} {
		if got := testCase.status.String(); got != testCase.want {
			t.Fatalf("got %q, want %q", got, testCase.want)
		}
	}
}

// A service pointed at the binary the operator happened to run it from stops working
// the day they tidy their downloads.
func TestInstallBinaryCopiesAndIsRepeatable(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "downloaded")
	destination := filepath.Join(directory, "installed", Name)

	if err := os.WriteFile(source, []byte("binary"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	for range 2 {
		path, err := InstallBinary(source, destination)
		if err != nil {
			t.Fatalf("install: %v", err)
		}

		if path != destination {
			t.Fatalf("installed to %s, want %s", path, destination)
		}
	}

	contents, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(contents) != "binary" {
		t.Fatalf("copied the wrong bytes: %q", contents)
	}

	// The operator ran this file; an installer that deletes it is a nasty surprise.
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("the source binary was consumed: %v", err)
	}

	info, err := os.Stat(destination)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("the installed binary is not executable: %v", info.Mode())
	}
}

// Installing over itself must be a no-op rather than a truncated binary.
func TestInstallBinaryOverItselfIsHarmless(t *testing.T) {
	path := filepath.Join(t.TempDir(), Name)

	if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := InstallBinary(path, path); err != nil {
		t.Fatalf("install: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "binary" {
		t.Fatalf("the binary was damaged: %q, %v", contents, err)
	}
}

func TestDefaultsAreAbsolute(t *testing.T) {
	if path := DefaultInstallPath(); !filepath.IsAbs(path) {
		t.Fatalf("install path is relative: %s", path)
	}

	if path := DefaultStateDir(); !filepath.IsAbs(path) {
		t.Fatalf("state directory is relative: %s", path)
	}

	if path := DefaultLogPath(); path != "" && !filepath.IsAbs(path) {
		t.Fatalf("log path is relative: %s", path)
	}
}
