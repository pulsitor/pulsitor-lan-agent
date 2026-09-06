// Package logging gives the agent somewhere to write when nobody is watching a
// terminal.
//
// A foreground run logs to standard error and lets systemd or the operator's shell
// deal with it. A service does not have that luxury: launchd and the Windows service
// manager both start the process with no console attached, so anything written there
// goes nowhere at all. The file sink below is what those two use, and it caps its own
// size because an agent that runs for a year unattended must not be the reason a disk
// fills up.
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// DefaultMaxBytes is where a log file is rolled over. One generation is kept, so the
// agent's footprint is bounded at twice this whatever happens.
const DefaultMaxBytes = 10 << 20

// Sink is where the agent writes, and what has to be closed when it stops.
type Sink struct {
	io.Writer
	closer io.Closer
}

// Close releases the file, if the sink owns one. Standard error is never closed.
func (s *Sink) Close() error {
	if s.closer == nil {
		return nil
	}

	return s.closer.Close()
}

// New opens a sink. An empty path means standard error, which is what a foreground run
// and a systemd unit both want.
func New(path string, maxBytes int64) (*Sink, error) {
	if path == "" {
		return &Sink{Writer: os.Stderr}, nil
	}

	writer, err := newRotating(path, maxBytes)
	if err != nil {
		return nil, err
	}

	return &Sink{Writer: writer, closer: writer}, nil
}

// Logger builds the agent's logger over a sink.
//
// Timestamps are UTC: these files are read next to a server-side incident whose times
// are UTC, and a reader should not have to work out which zone the customer's machine
// was in.
func Logger(sink *Sink) *log.Logger {
	return log.New(sink, "", log.LstdFlags|log.LUTC)
}

// rotating is an append-only file that rolls over once it grows past a limit.
//
// Deliberately not a full log rotator: there is no compression, no dated names and no
// retention policy, because the agent is not the system's log manager. It only makes
// sure that an unattended process cannot grow without bound.
type rotating struct {
	guard sync.Mutex
	path  string
	max   int64
	size  int64
	file  *os.File
}

func newRotating(path string, maxBytes int64) (*rotating, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("log directory: %w", err)
	}

	writer := &rotating{path: path, max: maxBytes}
	if err := writer.open(); err != nil {
		return nil, err
	}

	return writer, nil
}

// open attaches to the log file, picking up wherever a previous run left off.
func (r *rotating) open() error {
	// 0600: the log names the networks and devices of the customer's LAN, which is not
	// something every account on the machine needs to read.
	file, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("log file %s: %w", r.path, err)
	}

	size := int64(0)
	if info, err := file.Stat(); err == nil {
		size = info.Size()
	}

	r.file, r.size = file, size

	return nil
}

// Write appends one record, rolling the file over first when it would not fit.
//
// A write that fails is reported to the caller but never fatal upstream: losing the log
// is not a reason to stop monitoring the network.
func (r *rotating) Write(record []byte) (int, error) {
	r.guard.Lock()
	defer r.guard.Unlock()

	if r.file == nil {
		return 0, os.ErrClosed
	}

	if r.size+int64(len(record)) > r.max {
		if err := r.rollOver(); err != nil {
			return 0, err
		}
	}

	written, err := r.file.Write(record)
	r.size += int64(written)

	return written, err
}

// rollOver moves the current file aside and starts a new one, keeping one generation.
//
// On Windows the rename cannot happen while the file is open, so it is closed first;
// that is also why a failure here has to leave a usable file behind rather than a
// closed handle the next write would panic on.
func (r *rotating) rollOver() error {
	if err := r.file.Close(); err != nil {
		return err
	}

	r.file = nil

	if err := os.Rename(r.path, r.path+".1"); err != nil && !os.IsNotExist(err) {
		// Reopen the original rather than leaving the agent with nowhere to write.
		if reopened := r.open(); reopened != nil {
			return reopened
		}

		return err
	}

	return r.open()
}

// Close releases the file.
func (r *rotating) Close() error {
	r.guard.Lock()
	defer r.guard.Unlock()

	if r.file == nil {
		return nil
	}

	file := r.file
	r.file = nil

	return file.Close()
}
