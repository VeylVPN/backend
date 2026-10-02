//go:build !windows

package winsvc

func Run(fn func() int) int {
	return fn()
}

func Active() bool {
	return false
}
