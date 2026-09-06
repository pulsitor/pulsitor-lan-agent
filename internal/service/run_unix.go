//go:build !windows

package service

import "context"

// Run executes work. systemd and launchd both supervise an ordinary foreground process
// and signal it to stop, which the caller has already wired into the context, so there
// is nothing to hand over to here.
func Run(ctx context.Context, work func(context.Context) error) error {
	return work(ctx)
}
