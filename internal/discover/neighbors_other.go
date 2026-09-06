//go:build !windows && !linux && !darwin && !freebsd && !openbsd && !netbsd

package discover

// Neighbors has no implementation on this platform yet, so discovery falls back to what
// answered the sweep — addresses without MAC addresses.
func Neighbors() []Neighbor {
	return []Neighbor{}
}
