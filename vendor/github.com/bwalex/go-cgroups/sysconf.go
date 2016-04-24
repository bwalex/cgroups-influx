// +build cgo,linux

package cgroups

/*
#include <unistd.h>
*/
import "C"

func sysconfClockTicks() uint64 {
	val := C.sysconf(C._SC_CLK_TCK)

	if int(val) < 0 {
		panic("_SC_CLK_TCK negative!")
	}

	return uint64(val)
}
