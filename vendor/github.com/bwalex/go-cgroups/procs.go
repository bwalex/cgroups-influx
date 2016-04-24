package cgroups

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func GetProcs(cg Cgroup) ([]int, error) {
	pids := make([]int, 0, 16)

	path, err := GetCgroupPath(cg, ControllerCpu, "cgroup.procs")
	if err == ErrNoCgroup {
		return pids, err
	}

	fd, err := os.Open(path)
	if err != nil {
		return pids, err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		str := strings.TrimSpace(scanner.Text())
		value, err := strconv.ParseInt(str, 10, 32)

		if err == nil {
			pids = append(pids, int(value))
		}
	}

	return pids, nil
}
