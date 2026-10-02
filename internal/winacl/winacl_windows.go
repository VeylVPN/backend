package winacl

import (
	"syscall"
	"unsafe"
)

const (
	seFileObject              = 1
	daclSecurityInformation   = 0x4
	protectedDaclSecurityInfo = 0x80000000
	sddlRevision1             = 1
)

var (
	advapi32                 = syscall.NewLazyDLL("advapi32.dll")
	procConvertSDDL          = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescDacl  = advapi32.NewProc("GetSecurityDescriptorDacl")
	procSetNamedSecurityInfo = advapi32.NewProc("SetNamedSecurityInfoW")
)

func Protect(path string, dir bool, grants []Grant) error {
	sddl, err := SDDL(dir, grants)
	if err != nil {
		return err
	}
	s, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return err
	}
	var sd uintptr
	r, _, e := procConvertSDDL.Call(uintptr(unsafe.Pointer(s)), sddlRevision1, uintptr(unsafe.Pointer(&sd)), 0)
	if r == 0 {
		return e
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	var present, defaulted int32
	var dacl uintptr
	r, _, e = procGetSecurityDescDacl.Call(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted)))
	if r == 0 {
		return e
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, _ = procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(p)), seFileObject, daclSecurityInformation|protectedDaclSecurityInfo, 0, 0, dacl, 0)
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}
