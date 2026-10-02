package privdrop

import (
	"syscall"
	"unsafe"
)

const tokenElevation = 20

func To(name string) error {
	return nil
}

func Elevated() bool {
	var t syscall.Token
	p, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	if err := syscall.OpenProcessToken(p, syscall.TOKEN_QUERY, &t); err != nil {
		return false
	}
	defer t.Close()
	var elevated uint32
	var n uint32
	if err := syscall.GetTokenInformation(t, tokenElevation, (*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &n); err != nil {
		return false
	}
	return elevated != 0
}

func RequireRoot() error {
	if !Elevated() {
		return ErrNotRoot
	}
	return nil
}
