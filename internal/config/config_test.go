package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveReplacesIdentityWithoutPartialReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	state := &State{Identity: &Identity{Code: "test", Secret: "permanent-secret"}}
	if err := Save(path, state); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		for {
			select {
			case <-done:
				result <- nil
				return
			default:
				loaded, err := Load(path)
				if err != nil {
					result <- err
					return
				}
				if loaded.Identity == nil || loaded.Identity.Secret != state.Identity.Secret {
					result <- os.ErrInvalid
					return
				}
			}
		}
	}()
	for i := 0; i < 40; i++ {
		update := &State{Identity: state.Identity, Runtime: &Runtime{CheckInIntervalSeconds: i + 15}}
		if err := Save(path, update); err != nil {
			close(done)
			<-result
			t.Fatal(err)
		}
	}
	close(done)
	if err := <-result; err != nil {
		t.Fatalf("reader saw a partial identity: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("secret permissions: %v", info.Mode())
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".identity-*"))
	if err != nil || len(leftovers) > 0 {
		t.Fatalf("temporary secrets left behind: %v (%v)", leftovers, err)
	}
}

func TestFailedRenameLeavesDestinationUntouchedAndCleansTemporarySecret(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "identity.json")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(destination, "existing")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	err := Save(destination, &State{Identity: &Identity{Code: "test", Secret: "secret"}})
	if err == nil {
		t.Fatal("expected rename to fail")
	}
	contents, err := os.ReadFile(sentinel)
	if err != nil || string(contents) != "keep" {
		t.Fatal("failed save damaged destination")
	}
	leftovers, err := filepath.Glob(filepath.Join(directory, ".identity-*"))
	if err != nil || len(leftovers) > 0 {
		t.Fatalf("temporary secrets left behind: %v (%v)", leftovers, err)
	}
}

// An enrollment token is good once, so the agent must find out that it cannot store an
// identity before it trades the token for one.
func TestEnsureWritableAcceptsAPathItCanCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "identity.json")

	if err := EnsureWritable(path); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("the directory was not created: %v", err)
	}

	// The check must leave nothing behind for the real write to trip over.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf("the writability probe left %d file(s) behind", len(entries))
	}
}

func TestEnsureWritableRefusesADirectoryItCannotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere, so there is nothing to refuse")
	}

	directory := filepath.Join(t.TempDir(), "readonly")

	if err := os.Mkdir(directory, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err := EnsureWritable(filepath.Join(directory, "identity.json"))
	if err == nil {
		t.Fatal("a read-only directory was accepted")
	}

	// The operator has two ways out and the message has to name them, or an
	// unprivileged first run is just "permission denied" and a guess.
	if !strings.Contains(err.Error(), "sudo") || !strings.Contains(err.Error(), "--state") {
		t.Fatalf("the error does not say how to fix it: %v", err)
	}
}
