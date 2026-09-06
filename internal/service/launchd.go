package service

// As with the systemd unit, the launchd job is rendered here rather than behind the
// Darwin build tag: a plist launchd cannot parse fails at boot on a customer's machine,
// which is the worst possible place to discover it, and a test that only a Mac can run
// is a test that mostly does not.

import (
	"encoding/xml"
	"os"
	"strings"
)

// Label is launchd's name for the job, and the only handle every launchctl subcommand
// accepts.
const Label = "com.pulsitor.lan-agent"

// plist renders the launchd job.
//
// Built with encoding/xml rather than a formatted string: a customer's install path can
// contain an ampersand or a quote, and a plist launchd cannot parse fails at boot, long
// after whoever installed it has stopped watching.
func plist(config Config) (string, error) {
	arguments := append([]string{config.Executable}, config.Arguments...)

	body := &plistDict{}
	body.add("Label", plistString{Value: Label})
	body.add("ProgramArguments", plistArray{Strings: asStrings(arguments)})
	body.add("RunAtLoad", plistTrue{})
	body.add("KeepAlive", plistTrue{})

	// launchd's own floor is 10 seconds; naming it keeps a crash loop from being
	// throttled into silence without explanation.
	body.add("ThrottleInterval", plistInteger{Value: 10})
	body.add("ProcessType", plistString{Value: "Background"})

	if config.LogPath != "" {
		// The agent rotates its own log; these only catch a panic on the way out,
		// which by definition never reaches the logger.
		body.add("StandardOutPath", plistString{Value: config.LogPath})
		body.add("StandardErrorPath", plistString{Value: config.LogPath})
	}

	encoded, err := xml.MarshalIndent(struct {
		XMLName xml.Name `xml:"plist"`
		Version string   `xml:"version,attr"`
		Dict    *plistDict
	}{Version: "1.0", Dict: body}, "", "\t")
	if err != nil {
		return "", err
	}

	return xml.Header +
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
		string(encoded) + "\n", nil
}

// The property list vocabulary, kept to the handful of types a launchd job needs.
type plistDict struct {
	XMLName xml.Name `xml:"dict"`
	Entries []any
}

func (d *plistDict) add(key string, value any) {
	d.Entries = append(d.Entries, plistKey{Value: key}, value)
}

type plistKey struct {
	XMLName xml.Name `xml:"key"`
	Value   string   `xml:",chardata"`
}

type plistString struct {
	XMLName xml.Name `xml:"string"`
	Value   string   `xml:",chardata"`
}

type plistInteger struct {
	XMLName xml.Name `xml:"integer"`
	Value   int      `xml:",chardata"`
}

type plistTrue struct {
	XMLName xml.Name `xml:"true"`
}

type plistArray struct {
	XMLName xml.Name `xml:"array"`
	Strings []plistString
}

func asStrings(values []string) []plistString {
	out := make([]plistString, 0, len(values))

	for _, value := range values {
		out = append(out, plistString{Value: value})
	}

	return out
}

// The command boundary lets the lifecycle be tested on every release platform.
type launchdService struct {
	domain  string // Empty means the installed system daemon.
	path    string
	label   string
	command func(...string) ([]byte, error)
}

func (s launchdService) installed() error {
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return ErrNotInstalled
	} else {
		return err
	}
}

func (s launchdService) start() error {
	if err := s.installed(); err != nil {
		return err
	}
	target := s.target()
	if _, err := s.command("enable", target); err != nil {
		return err
	}
	if _, err := s.command("print", target); err != nil {
		// bootout removes the definition as well as stopping its process.
		if _, err := s.command("bootstrap", s.launchDomain(), s.path); err != nil {
			return err
		}
	}
	_, err := s.command("kickstart", target)
	return err
}

func (s launchdService) stop() error {
	if err := s.installed(); err != nil {
		return err
	}
	target := s.target()
	if _, err := s.command("bootout", target); err != nil {
		// Repeated stops are harmless only when launchd confirms that it has no job.
		output, queryErr := s.command("print", target)
		if queryErr != nil && strings.Contains(string(output), "Could not find service") {
			return nil
		}
		return err
	}
	return nil
}

func (s launchdService) query() (Status, error) {
	if err := s.installed(); err == ErrNotInstalled {
		return Status{}, nil
	} else if err != nil {
		return Status{}, err
	}
	output, err := s.command("print", s.target())
	if err != nil {
		if strings.Contains(string(output), "Could not find service") {
			return Status{Installed: true, Detail: "not loaded"}, nil
		}
		return Status{}, err
	}
	running := false
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "state = running" {
			running = true
			break
		}
	}
	detail := "loaded"
	if running {
		detail = "loaded, running"
	}
	return Status{Installed: true, Running: running, Detail: detail}, nil
}

func (s launchdService) launchDomain() string {
	if s.domain != "" {
		return s.domain
	}
	return "system"
}

func (s launchdService) target() string { return s.launchDomain() + "/" + s.label }
