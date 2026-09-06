//go:build windows

package service

import "path/filepath"

// DefaultStateDir is where the identity lives on this platform.
func DefaultStateDir() string {
	return filepath.Join(programData(), "Pulsitor", "LANAgent")
}
