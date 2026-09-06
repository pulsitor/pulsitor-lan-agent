package service

import (
	"os"
	"path/filepath"
	"testing"
)

// referenceConfig is the shape a default installation produces. The files under
// packaging/ are what an administrator who manages units with configuration management
// copies rather than running `service install`, so they have to be the same files the
// installer would have written — a reference that drifted from the code is worse than
// no reference at all.
func referenceConfig() Config {
	return Config{
		Executable: "/usr/local/bin/" + Name,
		// No --server: the endpoint is compiled into the binary.
		Arguments: []string{"--state", "/var/lib/" + Name + "/identity.json"},
	}
}

func referenceLaunchdConfig() Config {
	return Config{
		Executable: "/usr/local/bin/" + Name,
		Arguments: []string{
			"--state", "/Library/Application Support/Pulsitor/LANAgent/identity.json",
			"--log-file", "/Library/Logs/Pulsitor/lan-agent.log",
		},
		LogPath: "/Library/Logs/Pulsitor/lan-agent.log",
	}
}

func TestCheckedInSystemdUnitMatchesWhatWeWould(t *testing.T) {
	want := systemdUnit(referenceConfig(), "pulsitor-agent", "/var/lib/"+Name)

	compare(t, filepath.Join("..", "..", "packaging", Name+".service"), want)
}

func TestCheckedInLaunchdPlistMatchesWhatWeWould(t *testing.T) {
	want, err := plist(referenceLaunchdConfig())
	if err != nil {
		t.Fatalf("plist: %v", err)
	}

	compare(t, filepath.Join("..", "..", "packaging", Label+".plist"), want)
}

// compare reports a drifted file with the command that fixes it, because the useful
// half of this test is telling the next person what to do about the failure.
func compare(t *testing.T, path, want string) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	if string(got) != want {
		t.Fatalf("%s has drifted from the installer.\nRegenerate it with: go test ./internal/service/ -run Reference -update\n\nwant:\n%s\n\ngot:\n%s", path, want, got)
	}
}

// TestReferenceFiles rewrites the checked-in copies when run with -update.
func TestReferenceFiles(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate the packaging reference files")
	}

	unit := systemdUnit(referenceConfig(), "pulsitor-agent", "/var/lib/"+Name)

	if err := os.WriteFile(filepath.Join("..", "..", "packaging", Name+".service"), []byte(unit), 0o644); err != nil {
		t.Fatalf("write unit: %v", err)
	}

	job, err := plist(referenceLaunchdConfig())
	if err != nil {
		t.Fatalf("plist: %v", err)
	}

	if err := os.WriteFile(filepath.Join("..", "..", "packaging", Label+".plist"), []byte(job), 0o644); err != nil {
		t.Fatalf("write plist: %v", err)
	}
}
