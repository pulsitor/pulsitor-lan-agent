//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Load the system DLL by absolute path, never from the working directory.
var advapi32 = syscall.NewLazyDLL(filepath.Join(os.Getenv("SystemRoot"), "System32", "advapi32.dll"))

var (
	startDispatcher     = advapi32.NewProc("StartServiceCtrlDispatcherW")
	registerHandler     = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	setServiceStatus    = advapi32.NewProc("SetServiceStatus")
	openSCManager       = advapi32.NewProc("OpenSCManagerW")
	createService       = advapi32.NewProc("CreateServiceW")
	openService         = advapi32.NewProc("OpenServiceW")
	deleteService       = advapi32.NewProc("DeleteService")
	startService        = advapi32.NewProc("StartServiceW")
	controlService      = advapi32.NewProc("ControlService")
	queryServiceStatus  = advapi32.NewProc("QueryServiceStatus")
	closeServiceHandle  = advapi32.NewProc("CloseServiceHandle")
	changeServiceConfig = advapi32.NewProc("ChangeServiceConfig2W")
)

// Service manager and service access rights, service types and start types.
const (
	scManagerAllAccess = 0x000F003F
	serviceAllAccess   = 0x000F01FF

	serviceWin32OwnProcess = 0x00000010
	serviceAutoStart       = 0x00000002
	serviceErrorNormal     = 0x00000001

	serviceStopped      = 0x00000001
	serviceStartPending = 0x00000002
	serviceStopPending  = 0x00000003
	serviceRunning      = 0x00000004

	serviceAcceptStop     = 0x00000001
	serviceAcceptShutdown = 0x00000004

	serviceControlStop         = 0x00000001
	serviceControlInterrogate  = 0x00000004
	serviceControlShutdown     = 0x00000005
	serviceControlPreShutdown  = 0x0000000F
	serviceAcceptPreShutdown   = 0x00000100
	serviceConfigDescription   = 0x00000001
	serviceConfigFailureAction = 0x00000002
)

// Errors the service manager returns that the agent has to tell apart from the rest.
const (
	// errNotStartedByManager is what the dispatcher returns when the binary was simply
	// run from a shell. It is the documented way to tell a service invocation from a
	// foreground one, and it is not a failure.
	errNotStartedByManager syscall.Errno = 1063

	errServiceExists         syscall.Errno = 1073
	errServiceDoesNotExist   syscall.Errno = 1060
	errServiceNotActive      syscall.Errno = 1062
	errServiceAlreadyRunning syscall.Errno = 1056
	errServiceMarkedDelete   syscall.Errno = 1072
)

// serviceTableEntry is one row of the table the dispatcher is handed. A zeroed entry
// terminates it.
type serviceTableEntry struct {
	Name *uint16
	Proc uintptr
}

// serviceStatus is the seven DWORDs the service manager polls.
type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

// serviceDescription carries the sentence services.msc shows under the name.
type serviceDescription struct {
	Description *uint16
}

// scAction is one step of the recovery policy; type 1 is "restart the service".
type scAction struct {
	Type  uint32
	Delay uint32
}

// serviceFailureActions is the recovery policy. Go's field alignment matches the C
// layout on both 32 and 64 bit: each pointer is aligned to its own width, exactly as
// the compiler pads the C struct.
type serviceFailureActions struct {
	ResetPeriod uint32
	RebootMsg   *uint16
	Command     *uint16
	ActionCount uint32
	Actions     *scAction
}

// The dispatcher hands control to a callback rather than returning, so the work, the
// context that stops it and the error it ended with have to live beside it.
var (
	serviceWork   func(context.Context) error
	serviceCancel context.CancelFunc
	serviceCtx    context.Context
	serviceResult error

	serviceHandle uintptr
	statusGuard   sync.Mutex
	lastState     uint32
	lastAccepted  uint32

	// Callbacks are registered once. Every syscall.NewCallback consumes one of a few
	// thousand process-wide slots, so building them per call would be a slow leak.
	callbacksOnce   sync.Once
	mainCallback    uintptr
	controlCallback uintptr
)

// Run executes work under the Windows service manager when the process was started by
// it, and in the foreground when it was not.
//
// Which of the two it is cannot be asked directly; the documented test is to offer
// oneself to the dispatcher and read the refusal. That is why this is tried first and
// the foreground path is the fallback, rather than the other way round.
func Run(ctx context.Context, work func(context.Context) error) error {
	inner, cancel := context.WithCancel(ctx)
	defer cancel()

	serviceWork, serviceCtx, serviceCancel = work, inner, cancel

	name, err := syscall.UTF16PtrFromString(Name)
	if err != nil {
		return err
	}

	// LazyProc.Call panics rather than erring when the symbol cannot be resolved, and
	// a monitoring agent that panics on startup because a system DLL was unusual is a
	// worse outcome than one that simply runs in the foreground.
	if err := available(startDispatcher, registerHandler, setServiceStatus); err != nil {
		return work(ctx)
	}

	prepareCallbacks()

	table := []serviceTableEntry{{Name: name, Proc: mainCallback}, {}}

	connected, _, errno := startDispatcher.Call(uintptr(unsafe.Pointer(&table[0])))
	if connected == 0 {
		if errors.Is(errno, errNotStartedByManager) {
			return work(ctx)
		}

		return fmt.Errorf("connecting to the service manager: %w", errno)
	}

	return serviceResult
}

// prepareCallbacks builds the two callbacks the service manager calls back into.
func prepareCallbacks() {
	callbacksOnce.Do(func() {
		mainCallback = syscall.NewCallback(serviceMain)
		controlCallback = syscall.NewCallback(serviceControl)
	})
}

// serviceMain is where the service manager hands over. It must report RUNNING promptly
// and STOPPED before it returns, or the manager kills the process for being unresponsive.
func serviceMain(argc uint32, argv **uint16) uintptr {
	name, err := syscall.UTF16PtrFromString(Name)
	if err != nil {
		return 0
	}

	handle, _, _ := registerHandler.Call(uintptr(unsafe.Pointer(name)), controlCallback, 0)
	if handle == 0 {
		return 0
	}

	serviceHandle = handle

	report(serviceStartPending, 0, 15000)
	report(serviceRunning, serviceAcceptStop|serviceAcceptShutdown|serviceAcceptPreShutdown, 0)

	serviceResult = serviceWork(serviceCtx)

	exitCode := uint32(0)
	if serviceResult != nil {
		// A non-zero exit is what makes the recovery policy fire, so a service that
		// died of a real fault comes back rather than sitting stopped until someone
		// notices.
		exitCode = 1
	}

	reportStopped(exitCode)

	return 0
}

// serviceControl handles the manager's requests. A stop is turned into a cancelled
// context, so the agent finishes the round it is in rather than being torn out of it.
func serviceControl(control, eventType uint32, eventData, callbackContext uintptr) uintptr {
	switch control {
	case serviceControlStop, serviceControlShutdown, serviceControlPreShutdown:
		// The wait hint is what buys the time to finish the round in hand; a sweep of
		// a full subnet has a thirty second ceiling of its own.
		report(serviceStopPending, 0, 45000)

		if serviceCancel != nil {
			serviceCancel()
		}
	case serviceControlInterrogate:
		statusGuard.Lock()
		state, accepted := lastState, lastAccepted
		statusGuard.Unlock()

		report(state, accepted, 0)
	}

	return 0
}

// report tells the manager where the service is up to.
func report(state, accepted, waitHint uint32) {
	statusGuard.Lock()
	defer statusGuard.Unlock()

	lastState, lastAccepted = state, accepted

	status := serviceStatus{
		ServiceType:      serviceWin32OwnProcess,
		CurrentState:     state,
		ControlsAccepted: accepted,
		WaitHint:         waitHint,
	}

	setServiceStatus.Call(serviceHandle, uintptr(unsafe.Pointer(&status)))
}

// reportStopped is the last thing the process says, and carries the exit code the
// recovery policy reads.
func reportStopped(exitCode uint32) {
	statusGuard.Lock()
	defer statusGuard.Unlock()

	lastState, lastAccepted = serviceStopped, 0

	status := serviceStatus{
		ServiceType:   serviceWin32OwnProcess,
		CurrentState:  serviceStopped,
		Win32ExitCode: exitCode,
	}

	setServiceStatus.Call(serviceHandle, uintptr(unsafe.Pointer(&status)))
}

// Install registers the agent with the service manager and starts it.
func Install(config Config) error {
	manager, err := openManager()
	if err != nil {
		return err
	}
	defer closeServiceHandle.Call(manager)

	name, err := syscall.UTF16PtrFromString(Name)
	if err != nil {
		return err
	}

	display, err := syscall.UTF16PtrFromString(DisplayName)
	if err != nil {
		return err
	}

	binary, err := syscall.UTF16PtrFromString(commandLine(config.Executable, config.Arguments))
	if err != nil {
		return err
	}

	// The log directory has to exist before the service starts: the sink is opened by
	// the agent itself, but a path under a directory nobody created fails on the first
	// write, which under a service is a failure nobody sees.
	if config.LogPath != "" {
		if err := os.MkdirAll(filepath.Dir(config.LogPath), 0o755); err != nil {
			return err
		}
	}

	handle, _, errno := createService.Call(
		manager,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(display)),
		serviceAllAccess,
		serviceWin32OwnProcess,
		serviceAutoStart,
		serviceErrorNormal,
		uintptr(unsafe.Pointer(binary)),
		0, 0, 0,
		// A null account is LocalSystem. LocalService would be tighter, but it cannot
		// write the machine-wide state directory the identity lives in without an ACL
		// change of its own, and an agent that cannot store its identity re-enrolls on
		// every restart.
		0, 0,
	)
	if handle == 0 {
		if errors.Is(errno, errServiceExists) || errors.Is(errno, errServiceMarkedDelete) {
			return fmt.Errorf("the %s service already exists; uninstall it first", Name)
		}

		return fmt.Errorf("creating the service: %w", errno)
	}
	defer closeServiceHandle.Call(handle)

	describe(handle)
	setRecoveryPolicy(handle)

	if started, _, errno := startService.Call(handle, 0, 0); started == 0 && !errors.Is(errno, errServiceAlreadyRunning) {
		return fmt.Errorf("the service was created but would not start: %w", errno)
	}

	return nil
}

// describe attaches the sentence services.msc shows. A failure here is cosmetic.
func describe(handle uintptr) {
	text, err := syscall.UTF16PtrFromString(Description)
	if err != nil {
		return
	}

	description := serviceDescription{Description: text}

	changeServiceConfig.Call(handle, serviceConfigDescription, uintptr(unsafe.Pointer(&description)))
}

// setRecoveryPolicy is the Windows counterpart of systemd's Restart=always.
//
// Without it a service that exits stays exited, and a monitoring agent that quietly
// stopped at three in the morning is worse than one that was never installed.
func setRecoveryPolicy(handle uintptr) {
	actions := []scAction{
		{Type: 1, Delay: 10000},
		{Type: 1, Delay: 30000},
		{Type: 1, Delay: 60000},
	}

	policy := serviceFailureActions{
		// A day without a failure clears the count, so a machine that reboots weekly
		// does not eventually exhaust the escalation.
		ResetPeriod: 86400,
		ActionCount: uint32(len(actions)),
		Actions:     &actions[0],
	}

	changeServiceConfig.Call(handle, serviceConfigFailureAction, uintptr(unsafe.Pointer(&policy)))
}

// Uninstall stops the service and removes it.
func Uninstall() error {
	manager, err := openManager()
	if err != nil {
		return err
	}
	defer closeServiceHandle.Call(manager)

	handle, err := open(manager)
	if err != nil {
		return err
	}
	defer closeServiceHandle.Call(handle)

	_ = stop(handle)

	if removed, _, errno := deleteService.Call(handle); removed == 0 {
		return fmt.Errorf("removing the service: %w", errno)
	}

	return nil
}

// Start starts an installed service.
func Start() error {
	manager, err := openManager()
	if err != nil {
		return err
	}
	defer closeServiceHandle.Call(manager)

	handle, err := open(manager)
	if err != nil {
		return err
	}
	defer closeServiceHandle.Call(handle)

	if started, _, errno := startService.Call(handle, 0, 0); started == 0 && !errors.Is(errno, errServiceAlreadyRunning) {
		return fmt.Errorf("starting the service: %w", errno)
	}

	return nil
}

// Stop stops an installed service.
func Stop() error {
	manager, err := openManager()
	if err != nil {
		return err
	}
	defer closeServiceHandle.Call(manager)

	handle, err := open(manager)
	if err != nil {
		return err
	}
	defer closeServiceHandle.Call(handle)

	return stop(handle)
}

// stop asks for a stop and waits for it, so an uninstall does not race the process it
// is removing.
func stop(handle uintptr) error {
	status := serviceStatus{}

	if sent, _, errno := controlService.Call(handle, serviceControlStop, uintptr(unsafe.Pointer(&status))); sent == 0 {
		if errors.Is(errno, errServiceNotActive) {
			return nil
		}

		return fmt.Errorf("stopping the service: %w", errno)
	}

	deadline := time.Now().Add(60 * time.Second)

	for time.Now().Before(deadline) {
		if queried, _, _ := queryServiceStatus.Call(handle, uintptr(unsafe.Pointer(&status))); queried == 0 {
			return nil
		}

		if status.CurrentState == serviceStopped {
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("the service did not stop within a minute")
}

// Query reports what the service manager knows about the service.
func Query() (Status, error) {
	manager, err := openManager()
	if err != nil {
		return Status{}, err
	}
	defer closeServiceHandle.Call(manager)

	handle, err := open(manager)
	if errors.Is(err, ErrNotInstalled) {
		return Status{}, nil
	}
	if err != nil {
		return Status{}, err
	}
	defer closeServiceHandle.Call(handle)

	status := serviceStatus{}
	if queried, _, errno := queryServiceStatus.Call(handle, uintptr(unsafe.Pointer(&status))); queried == 0 {
		return Status{}, fmt.Errorf("querying the service: %w", errno)
	}

	return Status{
		Installed: true,
		Running:   status.CurrentState == serviceRunning,
		Detail:    stateName(status.CurrentState),
	}, nil
}

// stateName is the manager's own wording for a state.
func stateName(state uint32) string {
	switch state {
	case serviceStopped:
		return "STOPPED"
	case serviceStartPending:
		return "START_PENDING"
	case serviceStopPending:
		return "STOP_PENDING"
	case serviceRunning:
		return "RUNNING"
	default:
		return fmt.Sprintf("state %d", state)
	}
}

// available reports whether every symbol needed is present, so a missing one becomes an
// error rather than the panic LazyProc.Call would raise.
func available(procedures ...*syscall.LazyProc) error {
	for _, procedure := range procedures {
		if err := procedure.Find(); err != nil {
			return fmt.Errorf("%w: %v", ErrUnsupported, err)
		}
	}

	return nil
}

// openManager connects to the service database, which needs administrator rights.
//
// Every management operation comes through here, which is why every symbol any of them
// touches is checked here too. Checking only the ones a particular function names looks
// tidier and is worse than no check at all: LazyProc.Call panics rather than erring on a
// symbol it cannot resolve, so a partial guard reads as covered while still crashing.
func openManager() (uintptr, error) {
	if err := available(
		openSCManager, openService, closeServiceHandle, queryServiceStatus,
		createService, startService, controlService, deleteService, changeServiceConfig,
	); err != nil {
		return 0, err
	}

	manager, _, errno := openSCManager.Call(0, 0, scManagerAllAccess)
	if manager == 0 {
		return 0, fmt.Errorf("opening the service manager (run this from an elevated prompt): %w", errno)
	}

	return manager, nil
}

// open finds the agent's own service.
func open(manager uintptr) (uintptr, error) {
	name, err := syscall.UTF16PtrFromString(Name)
	if err != nil {
		return 0, err
	}

	handle, _, errno := openService.Call(manager, uintptr(unsafe.Pointer(name)), serviceAllAccess)
	if handle == 0 {
		if errors.Is(errno, errServiceDoesNotExist) {
			return 0, ErrNotInstalled
		}

		return 0, fmt.Errorf("opening the service: %w", errno)
	}

	return handle, nil
}
