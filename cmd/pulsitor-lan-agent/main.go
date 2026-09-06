// Command pulsitor-lan-agent watches the devices on a local network and reports them
// to Pulsitor.
//
// It never accepts an inbound connection. Everything it does starts as an outgoing
// request, which is what lets it run behind NAT with no port forward and no VPN, and
// leaves it with no listening surface to attack.
//
// Two kinds of work, on two clocks the server sets: discovery sweeps a subnet to find
// what is on it, and a targeted probe checks one device the owner asked to be watched,
// at that monitoring's own interval.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pulsitor/pulsitor-lan-agent/internal/agent"
	"github.com/pulsitor/pulsitor-lan-agent/internal/config"
	"github.com/pulsitor/pulsitor-lan-agent/internal/logging"
	"github.com/pulsitor/pulsitor-lan-agent/internal/report"
	"github.com/pulsitor/pulsitor-lan-agent/internal/service"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := main1(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pulsitor-lan-agent: %v\n", err)
		os.Exit(1)
	}
}

// main1 is main with an error return, so every exit goes through one place.
func main1(arguments []string) error {
	if len(arguments) > 0 {
		switch arguments[0] {
		case "service":
			return serviceCommand(arguments[1:])
		case "version":
			fmt.Println(version)

			return nil
		}
	}

	return runCommand(arguments)
}

// options is everything both the foreground run and the service installation need.
type options struct {
	server      string
	statePath   string
	token       string
	tokenFile   string
	logPath     string
	execPath    string
	enrollOnly  bool
	once        bool
	verbose     bool
	showVersion bool
	purge       bool
}

// bind registers the flags. They are shared so that `service install --server X` and a
// foreground `--server X` cannot drift apart into meaning two different things.
func (o *options) bind(flags *flag.FlagSet, forService bool) {
	// The release endpoint is compiled in, so a customer never types it. The flag is
	// kept for running against a development server, not for configuring a deployment.
	flags.StringVar(&o.server, "server", report.DefaultServer, "Pulsitor endpoint (development override; the release default is compiled in)")
	flags.StringVar(&o.statePath, "state", envOr("PULSITOR_STATE", config.DefaultStatePath()), "Where the agent identity is kept")
	flags.StringVar(&o.token, "enroll", "", "One-time enrollment token; only needed the first time")
	flags.StringVar(&o.tokenFile, "enroll-file", "", "Read the enrollment token from a file")
	flags.BoolVar(&o.verbose, "verbose", false, "Log every round, not only the ones that carried news")

	if forService {
		flags.StringVar(&o.logPath, "log-file", service.DefaultLogPath(), "Where the service writes its log (empty for standard error)")
		flags.StringVar(&o.execPath, "exec-path", service.DefaultInstallPath(), "Where to install the binary the service will run")

		return
	}

	flags.StringVar(&o.logPath, "log-file", envOr("PULSITOR_LOG", ""), "Append the log to a file instead of standard error")
	flags.BoolVar(&o.enrollOnly, "enroll-only", false, "Enroll and save the identity, then exit")
	flags.BoolVar(&o.once, "once", false, "Run a single round and exit")
	flags.BoolVar(&o.showVersion, "version", false, "Print the version and exit")
}

// runCommand is the agent itself: enroll if needed, then work until told to stop.
func runCommand(arguments []string) error {
	flags := flag.NewFlagSet("pulsitor-lan-agent", flag.ExitOnError)
	flags.Usage = func() { usage(flags) }

	settings := &options{}
	settings.bind(flags, false)

	if err := flags.Parse(arguments); err != nil {
		return err
	}

	if settings.showVersion {
		fmt.Println(version)

		return nil
	}

	if err := settings.resolveToken(); err != nil {
		return err
	}

	client, err := settings.client()
	if err != nil {
		return err
	}

	sink, err := logging.New(settings.logPath, logging.DefaultMaxBytes)
	if err != nil {
		return err
	}
	defer sink.Close()

	logger := logging.Logger(sink)

	state, err := enrolledState(client, settings.statePath, settings.token)
	if err != nil {
		return fmt.Errorf("enrollment: %w", err)
	}

	if settings.enrollOnly {
		logger.Printf("identity ready as %s", state.Identity.Code)
		fmt.Printf("enrolled as %s\n", state.Identity.Code)

		return nil
	}

	logger.Printf("pulsitor-lan-agent %s reporting as %s to %s", version, state.Identity.Code, client.BaseURL)

	// A stop is a stop: a service manager restarts this process routinely, and
	// finishing the round in hand beats being killed in the middle of one.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runner := agent.Live(client, settings.statePath)
	runner.Logger = logger
	runner.Verbose = settings.verbose

	// On Windows this hands the process to the service manager when one started it,
	// and runs in the foreground when nobody did. Everywhere else it runs the work.
	err = service.Run(ctx, func(ctx context.Context) error {
		return runner.Run(ctx, state, settings.once)
	})

	logger.Printf("stopped")

	return err
}

// serviceCommand manages the agent's registration with the platform's service manager.
func serviceCommand(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("service needs one of: install, uninstall, start, stop, status")
	}

	action, rest := arguments[0], arguments[1:]

	switch action {
	case "install":
		return installService(rest)
	case "uninstall":
		return uninstallService(rest)
	case "start":
		return announce(service.Start(), "started")
	case "stop":
		return announce(service.Stop(), "stopped")
	case "status":
		status, err := service.Query()
		if err != nil {
			return err
		}

		fmt.Println(status)

		return nil
	default:
		return fmt.Errorf("unknown service action %q; expected install, uninstall, start, stop or status", action)
	}
}

// installService puts the binary somewhere permanent, redeems the enrollment token and
// registers the service.
//
// Enrollment happens here rather than on the service's first start on purpose: a token
// is good once, and a service that redeemed it in the background would leave nobody to
// tell when it failed. Doing it in the foreground means the operator finds out now.
func installService(arguments []string) error {
	flags := flag.NewFlagSet("service install", flag.ExitOnError)

	settings := &options{}
	settings.bind(flags, true)

	if err := flags.Parse(arguments); err != nil {
		return err
	}

	if err := settings.resolveToken(); err != nil {
		return err
	}

	client, err := settings.client()
	if err != nil {
		return err
	}

	state, err := enrolledState(client, settings.statePath, settings.token)
	if err != nil {
		return fmt.Errorf("enrollment: %w", err)
	}

	running, err := service.Executable()
	if err != nil {
		return err
	}

	installed, err := service.InstallBinary(running, settings.execPath)
	if err != nil {
		return err
	}

	// No endpoint in the service definition unless one was overridden: the compiled-in
	// default is the whole point, and repeating it in a file only creates a second
	// place for it to be wrong after an upgrade.
	arguments = []string{"--state", settings.statePath}

	if client.BaseURL != report.DefaultServer {
		arguments = append([]string{"--server", client.BaseURL}, arguments...)
	}

	if settings.logPath != "" {
		arguments = append(arguments, "--log-file", settings.logPath)
	}

	if settings.verbose {
		arguments = append(arguments, "--verbose")
	}

	if err := service.Install(service.Config{
		Executable: installed,
		Arguments:  arguments,
		LogPath:    settings.logPath,
	}); err != nil {
		return err
	}

	fmt.Printf("installed %s as %s, enrolled as %s\n", installed, service.Name, state.Identity.Code)

	if settings.logPath != "" {
		fmt.Printf("logging to %s\n", settings.logPath)
	}

	return nil
}

// uninstallService removes the service, and with --purge the identity it was using.
func uninstallService(arguments []string) error {
	flags := flag.NewFlagSet("service uninstall", flag.ExitOnError)

	settings := &options{}
	flags.StringVar(&settings.statePath, "state", envOr("PULSITOR_STATE", config.DefaultStatePath()), "Where the agent identity is kept")
	flags.BoolVar(&settings.purge, "purge", false, "Also delete the stored identity")

	if err := flags.Parse(arguments); err != nil {
		return err
	}

	if err := service.Uninstall(); err != nil && !errors.Is(err, service.ErrNotInstalled) {
		return err
	} else if err != nil {
		fmt.Println("the service was not installed")
	} else {
		fmt.Printf("removed the %s service\n", service.Name)
	}

	if !settings.purge {
		fmt.Printf("the identity at %s was left in place; pass --purge to delete it\n", settings.statePath)

		return nil
	}

	// The agent stays in the customer's account until they remove it there. Saying so
	// is the difference between a clean uninstall and a mystery agent that never
	// reports again.
	if err := os.Remove(settings.statePath); err != nil && !os.IsNotExist(err) {
		return err
	}

	fmt.Printf("deleted %s; remove the agent in Pulsitor as well\n", settings.statePath)

	return nil
}

// announce turns a management action into a line the operator can read.
func announce(err error, done string) error {
	if errors.Is(err, service.ErrNotInstalled) {
		return fmt.Errorf("the %s service is not installed; run `%s service install` first", service.Name, service.Name)
	}

	if err != nil {
		return err
	}

	fmt.Printf("%s %s\n", service.Name, done)

	return nil
}

// resolveToken reads the enrollment token from wherever it was given.
//
// A file is offered because a token on a command line ends up in the shell history and
// in every process listing on the machine, and it is good for exactly one enrollment.
func (o *options) resolveToken() error {
	if o.tokenFile == "" {
		return nil
	}

	if o.token != "" {
		return fmt.Errorf("use either --enroll or --enroll-file")
	}

	raw, err := os.ReadFile(o.tokenFile)
	if err != nil {
		return fmt.Errorf("read enrollment token: %w", err)
	}

	o.token = strings.TrimSpace(string(raw))

	return nil
}

// client validates the server address and builds the client for it.
func (o *options) client() (*report.Client, error) {
	o.server = strings.TrimRight(o.server, "/")

	if o.server == "" {
		return nil, fmt.Errorf("--server was given as empty; leave it out to use the compiled-in endpoint")
	}

	if err := report.ValidateURL(o.server); err != nil {
		return nil, err
	}

	if o.statePath == "" {
		return nil, fmt.Errorf("no --state path given")
	}

	if absolute, err := filepath.Abs(o.statePath); err == nil {
		o.statePath = absolute
	}

	return report.New(o.server, version), nil
}

// enrolledState loads the stored state, enrolling first when there is none.
func enrolledState(client *report.Client, statePath, token string) (*config.State, error) {
	state, err := config.Load(statePath)
	if err != nil {
		return nil, err
	}

	if state.Identity != nil {
		if state.Server != "" && state.Server != client.BaseURL {
			return nil, fmt.Errorf("identity belongs to a different server; use a separate --state path")
		}
		if token != "" {
			return nil, fmt.Errorf("identity already exists; use a separate --state path for re-enrollment")
		}
		if state.Server == "" {
			state.Server = client.BaseURL
			if err := config.Save(statePath, state); err != nil {
				return nil, err
			}
		}

		return state, nil
	}

	if token == "" {
		return nil, fmt.Errorf("no identity at %s and no --enroll token given", statePath)
	}

	// Before the token is spent, not after: it is good once, and an identity that
	// cannot be stored is an identity that is lost.
	if err := config.EnsureWritable(statePath); err != nil {
		return nil, err
	}

	identity, err := client.Enroll(token)
	if err != nil {
		return nil, err
	}

	state = &config.State{Identity: identity, Server: client.BaseURL}

	if err := config.Save(statePath, state); err != nil {
		return nil, fmt.Errorf("enrolled as %s but could not store the identity: %w", identity.Code, err)
	}

	return state, nil
}

// usage is what `--help` prints.
func usage(flags *flag.FlagSet) {
	out := flags.Output()

	fmt.Fprintf(out, `pulsitor-lan-agent %s

Reports the devices on this network to Pulsitor.

Usage:
  pulsitor-lan-agent [flags]                 run in the foreground
  pulsitor-lan-agent service install [flags] enroll, install and start the service
  pulsitor-lan-agent service uninstall [--purge]
  pulsitor-lan-agent service start|stop|status
  pulsitor-lan-agent version

Reports to %s unless --server says otherwise.

Flags:
`, version, report.DefaultServer)

	flags.PrintDefaults()

	fmt.Fprintf(out, `
The enrollment token is good once. It is exchanged for a permanent identity kept in
%s, after which --enroll is no longer needed.
`, config.DefaultStatePath())
}

// envOr reads an environment variable, falling back to a default.
func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}

	return fallback
}
