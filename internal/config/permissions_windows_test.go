//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Inspect the actual filesystem ACL with an independent Windows API consumer. Run
// in an elevated session, as on the Windows CI runner and in a service installation.
func assertWindowsStateACL(t *testing.T, path string) {
	t.Helper()
	script := `$ErrorActionPreference='Stop'
$acl=Get-Acl -LiteralPath $env:PULSITOR_ACL_TEST_PATH
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'Unexpected owner' }
if (-not $acl.AreAccessRulesProtected) { throw 'DACL inheritance is enabled' }
$rules=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
if ($rules.Count -ne 2) { throw "Unexpected ACE count: $($rules.Count)" }
$seen=@{}
foreach ($rule in $rules) {
 $sid=$rule.IdentityReference.Value
 if ($sid -ne 'S-1-5-18' -and $sid -ne 'S-1-5-32-544') { throw "Unexpected principal: $sid" }
 if ($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl') { throw "Unexpected access: $rule" }
 $seen[$sid]=$true
}
if ($seen.Count -ne 2) { throw 'SYSTEM or Administrators is missing' }
`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "PULSITOR_ACL_TEST_PATH="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ACL at %s: %v: %s", path, err, out)
	}
}

func TestWindowsIdentityPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "identity.json")
	// Enrollment preflight must protect the directory before any credential exists.
	if err := EnsureWritable(path); err != nil {
		t.Fatal(err)
	}
	assertWindowsStateACL(t, filepath.Dir(path))
	state := &State{Identity: &Identity{Code: "test", Secret: "secret"}}
	for i := 0; i < 3; i++ {
		state.Runtime = &Runtime{CheckInIntervalSeconds: 15 + i}
		if err := Save(path, state); err != nil {
			t.Fatal(err)
		}
		assertWindowsStateACL(t, path)
		loaded, err := Load(path)
		if err != nil || loaded.Identity.Secret != "secret" || loaded.Runtime.CheckInIntervalSeconds != 15+i {
			t.Fatalf("read after replacement: %+v / %v", loaded, err)
		}
	}
	// The temporary file is protected before the caller writes the credential.
	f, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := protectStateFile(f.Name()); err != nil {
		t.Fatal(err)
	}
	assertWindowsStateACL(t, f.Name())
}

func TestWindowsRepairsExistingIdentityPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte(`{"identity":{"agent_code":"test","agent_secret":"secret"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Simulate an older install that granted ordinary users explicit read access.
	if err := restrictStateAccess(path, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	assertWindowsStateACL(t, path)
	assertWindowsStateACL(t, filepath.Dir(path))
}
