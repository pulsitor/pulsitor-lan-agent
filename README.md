# Pulsitor LAN agent

Discovers the devices on a local network and reports them to Pulsitor, where they become
an inventory the user picks from. A device that gets picked becomes an ordinary Pulsitor
monitoring, with the same incidents and notification channels as everything else.

One static binary, no runtime to install beside it, on Linux, macOS and Windows. It
knows which Pulsitor to report to without being told: the endpoint is compiled in, so an
enrollment token is the only thing a customer ever has to carry across.

## What it does, and what it deliberately does not

It **never accepts an inbound connection**. Every exchange starts as an outgoing request,
so it runs behind NAT with no port forward and no VPN, and leaves no listening surface to
attack.

It **scans only the networks the server has enabled**, and only from the set of private
ranges. The agent reports which networks it is attached to; whether any of them is swept
is the user's decision. A compromised server cannot point an agent at a network of its
choosing, and a network wider than 1024 hosts is refused outright.

It **decides nothing**. Whether a device is missing, whether its address changed and
whether either is worth an incident are judgements the server makes.

## Installing

Get an enrollment token from Pulsitor first. It is good once.

### Linux and macOS

```
curl -fsSL https://github.com/pulsitor/pulsitor-lan-agent/releases/latest/download/install.sh \
  | sudo sh -s -- --enroll <token>
```

The script downloads the right build for the machine from the latest GitHub release,
checks it against that release's `SHA256SUMS`, and then hands over to the agent's own
`service install`. Nothing is installed from an artefact whose checksum did not match.
Add `--version v1.2.3` to pin a release instead of taking the newest.

### Windows

From an elevated PowerShell prompt:

```powershell
$installer = "$env:TEMP\install.ps1"
Invoke-WebRequest https://github.com/pulsitor/pulsitor-lan-agent/releases/latest/download/install.ps1 -OutFile $installer
& $installer -EnrollToken <token>
```

### From a binary you already have

The installer is only a download-and-verify wrapper; the agent installs itself.

```
sudo ./pulsitor-lan-agent service install --enroll <token>
```

That one command does everything: it copies the binary somewhere permanent, redeems the
token for a permanent identity, writes the service definition for whichever platform it
is on, and starts it.

| platform | supervised by | definition |
|---|---|---|
| Linux | systemd | `/etc/systemd/system/pulsitor-lan-agent.service` |
| macOS | launchd | `/Library/LaunchDaemons/com.pulsitor.lan-agent.plist` |
| Windows | the service manager | the `pulsitor-lan-agent` service |

On all three it starts with the machine and restarts itself if it ever stops. On Linux it
runs as an unprivileged `pulsitor-agent` account holding only `CAP_NET_RAW`, created at
install time; where no account could be created it falls back to root and the unit says
so. macOS and Windows run it as the system account, which is what a daemon on those
platforms is.

## Running it

```
pulsitor-lan-agent service status
pulsitor-lan-agent service stop
pulsitor-lan-agent service start
pulsitor-lan-agent service uninstall [--purge]
```

`--purge` also deletes the stored identity. The agent still exists in the customer's
Pulsitor account until they remove it there.

To watch it work, run it in the foreground instead:

```
pulsitor-lan-agent --once --verbose
```

| flag | default | meaning |
|---|---|---|
| `--state` | platform default, below | Where the identity and last configuration live |
| `--enroll` | — | One-time token; only needed the first time |
| `--enroll-file` | — | Read the token from a file instead of the command line |
| `--log-file` | `$PULSITOR_LOG`, else standard error | Append the log to a file |
| `--verbose` | `false` | Log every round, not only the ones that carried news |
| `--once` | `false` | Run a single round and exit |
| `--enroll-only` | `false` | Enroll, store the identity and exit |
| `--server` | compiled in | Development override only — see below |

Prefer `--enroll-file` to `--enroll` in a script: an argument is visible in the shell
history and in every process listing on the machine for as long as the process runs.

### The endpoint

`report.DefaultServer` is the Pulsitor installation a released binary reports to, and it
is a constant in the source rather than a flag, an environment variable or a line in the
service definition. An endpoint the customer has to type is one they can mistype, and a
wrong one is an agent that enrolls nowhere; it also means there is no file on their
machine that can be edited to point the agent somewhere else.

`--server` overrides it for development. `service install` writes it into the service
definition **only** when it differs from the compiled default, so an ordinary install
produces a unit with no endpoint in it at all:

```
php -S 127.0.0.1:8123 -t public router.php   # a local Pulsitor
pulsitor-lan-agent --server http://127.0.0.1:8123 --state ./identity.json --enroll <token> --once --verbose
```

Plain HTTP is refused for anything but a literal loopback address: the report carries a
bearer credential.

### Where things live

| | state | log |
|---|---|---|
| Linux | `/var/lib/pulsitor-lan-agent/identity.json` | the journal — `journalctl -u pulsitor-lan-agent` |
| macOS | `/Library/Application Support/Pulsitor/LANAgent/identity.json` | `/Library/Logs/Pulsitor/lan-agent.log` |
| Windows | `%ProgramData%\Pulsitor\LANAgent\identity.json` | `%ProgramData%\Pulsitor\LANAgent\agent.log` |

The state file holds the agent's secret and is written `0600` on Unix. On Windows,
the state directory and identity use a protected DACL granting access only to SYSTEM
and Administrators. Existing identities are secured when loaded, and enrollment refuses
to spend a token if these permissions cannot be applied. Use an elevated prompt for
foreground runs on Windows, and a dedicated directory when overriding `--state`: its
directory permissions are restricted too.

A log file is capped at
10 MiB and one previous generation is kept, so an agent left running for a year cannot
be the reason a disk fills up. On Linux the default is no file at all, because systemd's
own journal is where an operator on that platform already looks.

By default the log carries lifecycle events, failures, discovery rounds and any device
whose answer changed. `--verbose` adds the rounds in between — on a fifteen second check
that is nearly six thousand lines a day, which is why it is not the default.

## How presence is decided

Presence is what answered a probe sent now. The operating system's neighbour table is
read only to put a MAC address on the hosts that replied — never to decide who is here.
An ARP entry outlives the device it describes by many minutes, so trusting it would keep
reporting a device that left the network as connected.

The agent also verifies **who** answered, not just that something did: an address is not
an identity once DHCP hands the lease on, and a false "up" hides a real outage.

The probe is an ICMP echo, and on each platform it uses the mechanism that does not need
to be root:

- **macOS** — an unprivileged datagram socket, which any user may open.
- **Linux** — the same socket, which most distributions allow; the installed service
  additionally holds `CAP_NET_RAW`, so it works even where they do not.
- **Windows** — `IcmpSendEcho` from the IP Helper API, which needs no raw socket and no
  `ping.exe`.

A host that ignores ICMP therefore reads as absent; the server's miss threshold and grace
period exist so that a single silent round is not an outage. If no probe can be sent at
all the agent still runs, but says so loudly and falls back to the neighbour table — with
the staleness that implies. Running it by hand on Linux without the service, where the
distribution forbids the unprivileged socket:

```
sudo setcap cap_net_raw+ep /usr/local/bin/pulsitor-lan-agent
```

## When something is wrong

The agent tells you what to do about a refusal rather than only that it happened. The
lines worth knowing:

| in the log | what it means |
|---|---|
| `this agent's identity is no longer accepted` | the agent was deleted in Pulsitor. It stops climbing its backoff and retries slowly rather than hammering a door that will not open; delete the state file and enroll again. |
| `this machine's clock is too far from the server's` | reports are signed with a timestamp the server checks. Turn on NTP. |
| `active discovery unavailable` | no ICMP socket could be opened. See the `setcap` line above. |
| `probe(s) never left the host` | the sweep could not put all its packets on the wire, so that network is reported as *not covered* rather than as empty. The server leaves those devices alone instead of walking a whole subnet offline. |
| `the clock stepped backwards` | an NTP correction on a machine with no battery-backed clock. The schedule was pulled back to it; nothing to do. |

## Building

`make build` for this machine, `make dist` for the release matrix. `make check` runs the
tests and vets **every** target platform, which is the check that matters here: three of
the files that decide whether the agent works on a platform compile only on that
platform, so building for the machine you are sat at proves very little.

```
make check                  # tests, plus vet across the whole matrix
make dist VERSION=v1.2.3    # dist/ with every binary, the installers and SHA256SUMS
```

Releases are cut by GitHub Actions, not by hand. Pushing a `v*` tag runs `make dist` —
which itself depends on `make check`, so nothing is published that did not pass the tests
and the whole-matrix vet — checks that the built binary reports the tag it was built for,
and uploads every artefact to the release. Publishing also waits for native Windows
identity ACL tests; the same tests run in CI. `.github/workflows/ci.yml` runs the same
checks plus `gofmt` on every push and pull request.

The install scripts fetch `releases/latest/download/<asset>`, which GitHub serves as a
redirect to the newest release. That needs no API call and no token, which is what keeps
the installer down to `curl` and `sha256sum`.

Every target is `CGO_ENABLED=0` and built with `-trimpath`, so one machine builds the
whole fleet, each artefact is a single static file, and the same source and version stamp
produce the same bytes — which is what makes the published checksums worth anything.

Release matrix: Linux amd64/arm64/arm/386, macOS arm64/amd64, Windows amd64/386/arm64.

The files under `packaging/` are the service definitions a default install produces, for
administrators who manage units with configuration management rather than running
`service install`. They are generated from the same code the installer uses and a test
fails if they drift; regenerate them with:

```
go test ./internal/service/ -run TestReferenceFiles -update
```

## Platform differences

Naming is reverse DNS only for now: a router that serves PTR records for its DHCP
clients gives most devices a name, and a network without a reverse zone leaves them
labelled by their address. mDNS, SSDP and NetBIOS discovery, and vendor lookup from the
IEEE OUI list, are not implemented yet.

There is no native ARP sweep. `AF_PACKET` exists only on Linux, so everywhere the agent
uses an ICMP sweep plus the system neighbour table — the MAC addresses are read from the
operating system rather than solicited directly. Identity is always the MAC where one is
known, because an IP address is not an identity: a DHCP lease renewal would otherwise
turn one device into two.

The neighbour table is read natively on each platform: `/proc/net/arp` on Linux,
`GetIpNetTable` on Windows, and `arp -an` on macOS and the BSDs, which is why it is read
once per round rather than once per device.
