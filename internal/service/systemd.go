package service

// The unit is rendered here rather than in the Linux file so that it can be tested from
// any machine. Almost everything that decides whether this agent works on a platform is
// behind a build tag, which means the developer running the tests is exactly the person
// who cannot check it — so whatever can be lifted out of the tag is.

import (
	"path/filepath"
	"strings"
)

// account is the unprivileged user the agent runs as when one can be created.
const account = "pulsitor-agent"

// unit renders the systemd unit.
//
// The hardening is not decoration. This process reads one file, opens one outgoing
// connection and needs one capability; anything it is allowed to do beyond that is
// surface an attacker gets for free if the agent is ever the way in.
func systemdUnit(config Config, owner, stateDir string) string {
	lines := []string{
		"[Unit]",
		"Description=" + DisplayName,
		"After=network-online.target",
		"Wants=network-online.target",
		"StartLimitIntervalSec=0",
		"",
		"[Service]",
		"Type=simple",
		"ExecStart=" + commandLine(config.Executable, config.Arguments),
		"Restart=always",
		"RestartSec=10",
		"",
	}

	if owner != "" {
		lines = append(lines,
			"# CAP_NET_RAW is what lets the agent open an ICMP socket without being root.",
			"User="+owner,
			"Group="+owner,
			"AmbientCapabilities=CAP_NET_RAW",
			"CapabilityBoundingSet=CAP_NET_RAW",
			"",
		)
	}

	lines = append(lines,
		"NoNewPrivileges=true",
		"PrivateTmp=true",
		"PrivateDevices=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"ProtectKernelTunables=true",
		"ProtectKernelModules=true",
		"ProtectControlGroups=true",
		"RestrictSUIDSGID=true",
		"RestrictNamespaces=true",
		"LockPersonality=true",
		"MemoryDenyWriteExecute=true",
		// AF_NETLINK is not optional, however much it looks like it should be: Go's
		// net.Interfaces() enumerates addresses over a netlink socket, so a unit
		// without it produces an agent that starts, reports and passes every health
		// check while discovering nothing at all — "route ip+net: netlinkrib: address
		// family not supported by protocol", once per round, in the journal.
		"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
		"ReadWritePaths="+strings.Join(writable(config, stateDir), " "),
		"",
		"[Install]",
		"WantedBy=multi-user.target",
		"",
	)

	return strings.Join(lines, "\n")
}

// statePathFrom digs the state path out of the arguments the service will be started
// with, so the unit grants write access to exactly that directory and no other.
func statePathFrom(config Config, stateDir string) string {
	for index, argument := range config.Arguments {
		if argument == "--state" && index+1 < len(config.Arguments) {
			return config.Arguments[index+1]
		}

		if value, ok := strings.CutPrefix(argument, "--state="); ok {
			return value
		}
	}

	return filepath.Join(stateDir, "identity.json")
}

// writable is every directory ProtectSystem=strict has to make an exception for.
//
// The state directory always, and the log directory when one was named: an operator who
// passes --log-file and then finds the service dying on a read-only filesystem has been
// given a unit that contradicts its own command line.
func writable(config Config, stateDir string) []string {
	paths := []string{filepath.Dir(statePathFrom(config, stateDir))}

	if config.LogPath == "" {
		return paths
	}

	directory := filepath.Dir(config.LogPath)
	if directory != paths[0] {
		paths = append(paths, directory)
	}

	return paths
}
