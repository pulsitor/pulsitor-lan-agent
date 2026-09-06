//go:build !windows && !linux && !darwin

package service

// The agent still runs in the foreground everywhere it compiles; only the integration
// with a service manager is missing, so these say so rather than pretending to work.

func Install(Config) error { return ErrUnsupported }
func Uninstall() error     { return ErrUnsupported }
func Start() error         { return ErrUnsupported }
func Stop() error          { return ErrUnsupported }

func Query() (Status, error) { return Status{}, ErrUnsupported }

// DefaultStateDir is where the identity lives on this platform.
func DefaultStateDir() string { return "/var/lib/" + Name }
