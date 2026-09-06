//go:build !windows

package config

import "os"

func prepareStateDirectory(path string) error { return os.MkdirAll(path, 0o700) }
func protectExistingState(string) error       { return nil }
func protectStateFile(string) error           { return nil } // CreateTemp already uses 0600.
