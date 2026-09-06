//go:build windows

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var securityDLL = syscall.NewLazyDLL(filepath.Join(os.Getenv("SystemRoot"), "System32", "advapi32.dll"))
var kernelDLL = syscall.NewLazyDLL(filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll"))
var convertDescriptor = securityDLL.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var descriptorOwner = securityDLL.NewProc("GetSecurityDescriptorOwner")
var descriptorDACL = securityDLL.NewProc("GetSecurityDescriptorDacl")
var setNamedSecurity = securityDLL.NewProc("SetNamedSecurityInfoW")
var localFree = kernelDLL.NewProc("LocalFree")

const (
	fileObject       = 1
	ownerInformation = 1
	daclInformation  = 4
	protectedDACL    = 0x80000000
	// Well-known SIDs are independent of the language of the Windows installation.
	stateFileSDDL      = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	stateDirectorySDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

func prepareStateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return restrictStateAccess(path, stateDirectorySDDL)
}

// Repair identities made by earlier versions before using their credential. A missing
// identity must remain a read-only check; enrollment prepares its directory later.
func protectExistingState(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := prepareStateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return protectStateFile(path)
}

func protectStateFile(path string) error { return restrictStateAccess(path, stateFileSDDL) }

// Never write a secret until this succeeds. The directory supplies a restrictive
// inherited ACL at creation; the file gets its own protected ACL before any bytes.
func restrictStateAccess(path, sddl string) error {
	for _, proc := range []*syscall.LazyProc{convertDescriptor, descriptorOwner, descriptorDACL, setNamedSecurity, localFree} {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("protecting agent identity: %w", err)
		}
	}
	text, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return err
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var descriptor uintptr
	if ok, _, errno := convertDescriptor.Call(uintptr(unsafe.Pointer(text)), 1, uintptr(unsafe.Pointer(&descriptor)), 0); ok == 0 {
		return fmt.Errorf("creating identity security descriptor: %w", errno)
	}
	defer localFree.Call(descriptor)
	var present, defaulted int32
	var acl uintptr
	if ok, _, errno := descriptorDACL.Call(descriptor, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&acl)), uintptr(unsafe.Pointer(&defaulted))); ok == 0 {
		return fmt.Errorf("reading identity DACL: %w", errno)
	}
	if present == 0 || acl == 0 {
		return fmt.Errorf("identity security descriptor has no DACL")
	}

	// An old directory may have been created by an ordinary user. Leaving that
	// user as owner would let them grant themselves access again despite the DACL.
	var owner uintptr
	if ok, _, errno := descriptorOwner.Call(descriptor, uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&defaulted))); ok == 0 {
		return fmt.Errorf("reading identity owner: %w", errno)
	}
	if owner == 0 {
		return fmt.Errorf("identity security descriptor has no owner")
	}
	code, _, _ := setNamedSecurity.Call(uintptr(unsafe.Pointer(name)), fileObject, ownerInformation|daclInformation|protectedDACL, owner, 0, acl, 0)
	if code != 0 {
		return fmt.Errorf("protecting %s (run from an elevated prompt): %w", path, syscall.Errno(code))
	}
	return nil
}
