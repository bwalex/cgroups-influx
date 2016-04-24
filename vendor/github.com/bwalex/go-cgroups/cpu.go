package cgroups

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

type CpuStat struct {
	// From cpuacct.stat
	UserTimeUs       uint64 /* in microseconds */
	SystemTimeUs     uint64 /* in microseconds */

	// From cpu.stat
	ThrottledTimeUs  uint64 /* in microseconds */
	Periods          uint64
	ThrottledPeriods uint64

	// Derived
	ThrottledPct     float64

	SampleTime       time.Time
}

type CpuDeltaStat struct {
	UsagePct       float64
	UserUsagePct   float64
	SystemUsagePct float64
}

const (
	ControllerCpu = "cpu"
)

func (stats CpuStat) Delta(prevStats CpuStat) CpuDeltaStat {
	return CalcCpuDeltaStats(stats, prevStats)
}

func CalcCpuDeltaStats(stats CpuStat, prevStats CpuStat) CpuDeltaStat {
	var deltaStat CpuDeltaStat

	userTimeDeltaUs := stats.UserTimeUs - prevStats.UserTimeUs
	systemTimeDeltaUs := stats.SystemTimeUs - prevStats.SystemTimeUs
	timeDeltaUs := stats.SampleTime.Sub(prevStats.SampleTime).Nanoseconds() / int64(time.Microsecond)

	deltaStat.UserUsagePct = 100.0 * float64(userTimeDeltaUs) / float64(timeDeltaUs)
	deltaStat.SystemUsagePct = 100.0 * float64(systemTimeDeltaUs) / float64(timeDeltaUs)
	deltaStat.UsagePct = 100.0 * float64(userTimeDeltaUs + systemTimeDeltaUs) / float64(timeDeltaUs)

	return deltaStat
}

var ticksPerSec = uint64(sysconfClockTicks())

func populateCpuStat(cg Cgroup, stat *CpuStat) error {
	path, err := GetCgroupPath(cg, ControllerCpu, "cpu.stat")
	if err == ErrNoCgroup {
		return err
	}

	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}

		switch parts[0] {
		case "nr_periods":
			stat.Periods = value
		case "nr_throttled":
			stat.ThrottledPeriods = value
		case "throttled_time":
			stat.ThrottledTimeUs = ticksToUs(value)
		}
	}

	if stat.Periods == 0 {
		stat.ThrottledPct = 0
	} else {
		stat.ThrottledPct = 100.0 * float64(stat.ThrottledPeriods) / float64(stat.Periods)
	}

	return nil
}

func populateCpuacctStat(cg Cgroup, stat *CpuStat) error {
	path, err := GetCgroupPath(cg, ControllerCpu, "cpuacct.stat")
	if err == ErrNoCgroup {
		return err
	}

	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}

		switch parts[0] {
		case "user":
			stat.UserTimeUs = ticksToUs(value)
		case "system":
			stat.SystemTimeUs = ticksToUs(value)
		}
	}
	return nil
}

func GetCpuStats(cg Cgroup) (CpuStat, error) {
	var stats CpuStat

	stats.SampleTime = time.Now()

	err := populateCpuStat(cg, &stats)
	if err != nil {
		return stats, err
	}

	err = populateCpuacctStat(cg, &stats)
	if err != nil {
		return stats, err
	}

	return stats, nil
}

func ticksToUs(ticks uint64) uint64 {
	return ticks * 1000 * 1000 / ticksPerSec
}
