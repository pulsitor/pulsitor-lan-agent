//go:build windows

package discover

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Load the system DLL by absolute path, never from the working directory.
var ipHelper = syscall.NewLazyDLL(filepath.Join(os.Getenv("SystemRoot"), "System32", "iphlpapi.dll"))
var createEcho = ipHelper.NewProc("IcmpCreateFile")
var sendEcho = ipHelper.NewProc("IcmpSendEcho")
var closeEcho = ipHelper.NewProc("IcmpCloseHandle")

// Windows' IP Helper API supports ICMP without raw socket privileges or ping.exe.
// Each worker owns its handle. A bounded pool also bounds outstanding OS requests.
func probe(ctx context.Context, hosts []net.IP, timeout time.Duration) ([]net.IP, int, error) {
	if len(hosts) == 0 {
		return nil, 0, nil
	}
	for _, proc := range []*syscall.LazyProc{createEcho, sendEcho, closeEcho} {
		if err := proc.Find(); err != nil {
			return nil, len(hosts), fmt.Errorf("%w: %v", ErrNoProbe, err)
		}
	}
	deadline := time.Now().Add(timeout)
	jobs := make(chan net.IP, len(hosts))
	for _, ip := range hosts {
		jobs <- ip
	}
	close(jobs)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var found []net.IP
	unsent := 0
	for range min(128, len(hosts)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle, _, _ := createEcho.Call()
			if handle == ^uintptr(0) || handle == 0 {
				for range jobs {
					mu.Lock()
					unsent++
					mu.Unlock()
				}
				return
			}
			defer closeEcho.Call(handle)
			for ip := range jobs {
				remaining := time.Until(deadline)
				ipv4 := ip.To4()
				if ctx.Err() != nil || remaining < time.Millisecond || ipv4 == nil {
					mu.Lock()
					unsent++
					mu.Unlock()
					continue
				}
				// First two DWORDs are Address and Status on both 32 and 64 bit Windows.
				// 256 bytes includes the reply structure, payload and ICMP error trailer.
				reply := make([]byte, 256)
				payload := []byte("pulsitor")
				count, _, callErr := sendEcho.Call(handle, uintptr(binary.LittleEndian.Uint32(ipv4)),
					uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0,
					uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)),
					uintptr(min(remaining, time.Second).Milliseconds()))
				mu.Lock()
				if count > 0 && binary.LittleEndian.Uint32(reply[4:8]) == 0 && net.IP(reply[:4]).Equal(ip) {
					found = append(found, ip)
				} else {
					status := uint32(0)
					if count > 0 {
						status = binary.LittleEndian.Uint32(reply[4:8])
					} else if errno, ok := callErr.(syscall.Errno); ok {
						status = uint32(errno)
					}
					// Only timeout and explicit destination-unreachable replies prove absence.
					if status != 11010 && (status < 11002 || status > 11005) {
						unsent++
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return found, unsent, nil
}
