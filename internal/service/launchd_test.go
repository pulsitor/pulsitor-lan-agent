package service

import (
	"strings"
	"testing"
)

// A plist launchd cannot parse fails at boot, long after whoever installed it stopped
// watching — so the characters a customer's path can actually contain are the test.
func TestPlistEscapesTheCharactersAPathCanHold(t *testing.T) {
	rendered, err := plist(Config{
		Executable: "/usr/local/bin/pulsitor-lan-agent",
		Arguments:  []string{"--server", "https://a.example?x=1&y=2", "--state", "/Library/Application Support/P & Q/identity.json"},
		LogPath:    "/Library/Logs/Pulsitor/lan-agent.log",
	})
	if err != nil {
		t.Fatalf("plist: %v", err)
	}

	if strings.Contains(rendered, "& co") || strings.Contains(rendered, "?x=1&y=2") {
		t.Fatalf("an ampersand reached the document unescaped:\n%s", rendered)
	}

	if !strings.Contains(rendered, "&amp;") {
		t.Fatalf("the ampersand was not escaped:\n%s", rendered)
	}

	for _, required := range []string{
		"<!DOCTYPE plist",
		"<key>Label</key>",
		"<string>" + Label + "</string>",
		"<key>ProgramArguments</key>",
		"<key>RunAtLoad</key>",
		"<key>KeepAlive</key>",
		"<key>StandardErrorPath</key>",
	} {
		if !strings.Contains(rendered, required) {
			t.Fatalf("the plist is missing %s:\n%s", required, rendered)
		}
	}
}

// Without a log path there is nothing to redirect to, and an empty StandardErrorPath
// would send launchd looking for a file called "".
func TestPlistOmitsRedirectionWithoutALogPath(t *testing.T) {
	rendered, err := plist(Config{Executable: "/usr/local/bin/pulsitor-lan-agent"})
	if err != nil {
		t.Fatalf("plist: %v", err)
	}

	if strings.Contains(rendered, "StandardErrorPath") {
		t.Fatalf("redirection was written without a path:\n%s", rendered)
	}
}
