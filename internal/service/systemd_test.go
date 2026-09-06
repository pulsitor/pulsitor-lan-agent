package service

import (
	"strings"
	"testing"
)

func TestUnitGrantsWriteAccessToTheStateDirectoryOnly(t *testing.T) {
	rendered := systemdUnit(Config{
		Executable: "/usr/local/bin/pulsitor-lan-agent",
		Arguments:  []string{"--state", "/opt/pulsitor/identity.json"},
	}, account, DefaultStateDir())

	if !strings.Contains(rendered, "ReadWritePaths=/opt/pulsitor\n") {
		t.Fatalf("the unit does not follow --state:\n%s", rendered)
	}

	for _, required := range []string{
		"ExecStart=/usr/local/bin/pulsitor-lan-agent --state /opt/pulsitor/identity.json",
		"Restart=always",
		"User=" + account,
		"AmbientCapabilities=CAP_NET_RAW",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(rendered, required) {
			t.Fatalf("the unit is missing %q:\n%s", required, rendered)
		}
	}
}

// A machine whose user tools are missing must still end up with a working agent, and a
// unit naming an account that does not exist refuses to start at all.
func TestUnitOmitsTheAccountWhenNoneCouldBeCreated(t *testing.T) {
	rendered := systemdUnit(Config{Executable: "/usr/local/bin/pulsitor-lan-agent"}, "", DefaultStateDir())

	if strings.Contains(rendered, "User=") || strings.Contains(rendered, "AmbientCapabilities=") {
		t.Fatalf("the unit names an account that was never created:\n%s", rendered)
	}
}

func TestStatePathFromReadsBothFlagForms(t *testing.T) {
	for _, testCase := range []struct {
		arguments []string
		want      string
	}{
		{[]string{"--state", "/opt/x/identity.json"}, "/opt/x/identity.json"},
		{[]string{"--state=/opt/y/identity.json"}, "/opt/y/identity.json"},
		{[]string{"--verbose"}, DefaultStateDir() + "/identity.json"},
		// A trailing --state with nothing after it must not read past the end.
		{[]string{"--state"}, DefaultStateDir() + "/identity.json"},
	} {
		if got := statePathFrom(Config{Arguments: testCase.arguments}, DefaultStateDir()); got != testCase.want {
			t.Fatalf("%v gave %s, want %s", testCase.arguments, got, testCase.want)
		}
	}
}

// ProtectSystem=strict makes the whole filesystem read-only bar what is named here, so a
// unit that grants the state directory and forgets the log directory is a service that
// dies on its first write.
func TestUnitGrantsTheLogDirectoryWhenOneWasNamed(t *testing.T) {
	rendered := systemdUnit(Config{
		Executable: "/usr/local/bin/pulsitor-lan-agent",
		Arguments:  []string{"--state", "/var/lib/pulsitor-lan-agent/identity.json"},
		LogPath:    "/var/log/pulsitor/agent.log",
	}, account, DefaultStateDir())

	if !strings.Contains(rendered, "ReadWritePaths=/var/lib/pulsitor-lan-agent /var/log/pulsitor\n") {
		t.Fatalf("the log directory is not writable:\n%s", rendered)
	}
}

// The same directory twice would be noise, not a second grant.
func TestUnitDoesNotRepeatADirectory(t *testing.T) {
	rendered := systemdUnit(Config{
		Executable: "/usr/local/bin/pulsitor-lan-agent",
		Arguments:  []string{"--state", "/var/lib/pulsitor-lan-agent/identity.json"},
		LogPath:    "/var/lib/pulsitor-lan-agent/agent.log",
	}, account, DefaultStateDir())

	if !strings.Contains(rendered, "ReadWritePaths=/var/lib/pulsitor-lan-agent\n") {
		t.Fatalf("the state directory was granted twice:\n%s", rendered)
	}
}
