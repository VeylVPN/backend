//go:build !linux

package panel

import "time"

func Notify(state string) error {
	return nil
}

func WatchdogInterval() time.Duration {
	return 0
}
