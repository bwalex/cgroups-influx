// +build !cgo !linux

package cgroups

func sysconfClockTicks() uint64 {
	return 100
}
