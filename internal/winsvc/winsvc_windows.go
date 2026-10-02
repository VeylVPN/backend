package winsvc

import (
	"errors"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	serviceWin32OwnProcess = 0x10

	stateStopped      = 1
	stateStartPending = 2
	stateStopPending  = 3
	stateRunning      = 4

	acceptStop     = 0x1
	acceptShutdown = 0x4

	ctrlStop        = 0x1
	ctrlInterrogate = 0x4
	ctrlShutdown    = 0x5
	ctrlPreshutdown = 0xF

	errServiceSpecific      = 1066
	errNotUnderSCM          = 1063
	errCallNotImplemented   = 120
	stopTimeout             = 25 * time.Second
	stopWaitHintMillisecond = 30000
)

var (
	advapi32                       = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDispatcher = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandler = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus           = advapi32.NewProc("SetServiceStatus")
)

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type tableEntry struct {
	name *uint16
	proc uintptr
}

var (
	mu          sync.Mutex
	handle      uintptr
	current     serviceStatus
	runFn       func() int
	exitCode    int
	stopAsked   bool
	active      bool
	mainCB      = syscall.NewCallback(serviceMain)
	handlerCB   = syscall.NewCallback(ctlHandler)
	emptyName   = [1]uint16{0}
	nameStorage []uint16
)

func Active() bool {
	mu.Lock()
	defer mu.Unlock()
	return active
}

func Run(fn func() int) int {
	runFn = fn
	table := [2]tableEntry{{name: &emptyName[0], proc: mainCB}, {}}
	r, _, err := procStartServiceCtrlDispatcher.Call(uintptr(unsafe.Pointer(&table[0])))
	if r == 0 {
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == errNotUnderSCM {
			return fn()
		}
		return 1
	}
	mu.Lock()
	defer mu.Unlock()
	return exitCode
}

func setStatus(state uint32, code int, hint uint32) {
	mu.Lock()
	defer mu.Unlock()
	setStatusLocked(state, code, hint)
}

func setStatusLocked(state uint32, code int, hint uint32) {
	s := serviceStatus{ServiceType: serviceWin32OwnProcess, CurrentState: state, WaitHint: hint}
	if state == stateRunning {
		s.ControlsAccepted = acceptStop | acceptShutdown
	}
	if state == stateStopped && code != 0 && !stopAsked {
		s.Win32ExitCode = errServiceSpecific
		s.ServiceSpecificExitCode = uint32(code)
	}
	if state == stateStartPending || state == stateStopPending {
		s.CheckPoint = current.CheckPoint + 1
	}
	current = s
	if handle != 0 {
		_, _, _ = procSetServiceStatus.Call(handle, uintptr(unsafe.Pointer(&current)))
	}
}

func serviceName(argc uint32, argv **uint16) *uint16 {
	if argc < 1 || argv == nil || *argv == nil {
		return &emptyName[0]
	}
	chars := unsafe.Slice(*argv, 257)
	var n []uint16
	for _, c := range chars[:256] {
		n = append(n, c)
		if c == 0 {
			break
		}
	}
	if n[len(n)-1] != 0 {
		n = append(n, 0)
	}
	nameStorage = n
	return &nameStorage[0]
}

func serviceMain(argc uint32, argv **uint16) uintptr {
	name := serviceName(argc, argv)
	h, _, _ := procRegisterServiceCtrlHandler.Call(uintptr(unsafe.Pointer(name)), handlerCB, 0)
	if h == 0 {
		return 0
	}
	mu.Lock()
	handle = h
	active = true
	setStatusLocked(stateStartPending, 0, 10000)
	mu.Unlock()
	done := make(chan int, 1)
	go func() { done <- runFn() }()
	setStatus(stateRunning, 0, 0)
	var code int
	select {
	case code = <-done:
	case <-Context().Done():
		select {
		case code = <-done:
		case <-time.After(stopTimeout):
			code = 0
		}
	}
	mu.Lock()
	exitCode = code
	setStatusLocked(stateStopped, code, 0)
	mu.Unlock()
	return 0
}

func ctlHandler(ctrl, eventType, eventData, context uintptr) uintptr {
	switch ctrl {
	case ctrlStop, ctrlShutdown, ctrlPreshutdown:
		mu.Lock()
		stopAsked = true
		setStatusLocked(stateStopPending, 0, stopWaitHintMillisecond)
		mu.Unlock()
		stop()
		return 0
	case ctrlInterrogate:
		mu.Lock()
		if handle != 0 {
			_, _, _ = procSetServiceStatus.Call(handle, uintptr(unsafe.Pointer(&current)))
		}
		mu.Unlock()
		return 0
	}
	return errCallNotImplemented
}
