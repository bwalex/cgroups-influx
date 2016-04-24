package cgroups

import (
	"bufio"
	"os"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type NetStat struct {
	RxBytes      uint64 `field:"0"`
	RxPackets    uint64 `field:"1"`
	RxErrors     uint64 `field:"2"`
	RxDrop       uint64 `field:"3"`
	RxFifo       uint64 `field:"4"`
	RxFrame      uint64 `field:"5"`
	RxCompressed uint64 `field:"6"`
	RxMulticast  uint64 `field:"7"`

	TxBytes      uint64 `field:"8"`
	TxPackets    uint64 `field:"9"`
	TxErrors     uint64 `field:"10"`
	TxDrop       uint64 `field:"11"`
	TxFifo       uint64 `field:"12"`
	TxFrame      uint64 `field:"13"`
	TxCompressed uint64 `field:"14"`
	TxMulticast  uint64 `field:"15"`

	SampleTime   time.Time
}

type NetItemizedStats struct {
	Stats map[string]NetStat
}

type NetDeltaStat struct {
	RxByteRate   uint64
	RxPacketRate uint64
	RxDropRate   float64
	RxErrorRate  float64
	TxByteRate   uint64
	TxPacketRate uint64
	TxDropRate   float64
	TxErrorRate  float64
}

func (stats NetStat) Delta(prevStats NetStat) NetDeltaStat {
	return CalcNetDeltaStats(stats, prevStats)
}

func CalcNetDeltaStats(stats NetStat, prevStats NetStat) NetDeltaStat {
	var deltaStat NetDeltaStat

	rxByteDelta := stats.RxBytes - prevStats.RxBytes
	rxPktDelta := stats.RxPackets - prevStats.RxPackets
	rxDropDelta := stats.RxDrop - prevStats.RxDrop
	rxErrorDelta := stats.RxErrors - prevStats.RxErrors
	txByteDelta := stats.TxBytes - prevStats.TxBytes
	txPktDelta := stats.TxPackets - prevStats.TxPackets
	txDropDelta := stats.TxDrop - prevStats.TxDrop
	txErrorDelta := stats.TxErrors - prevStats.TxErrors

	timeDeltaMs := uint64(stats.SampleTime.Sub(prevStats.SampleTime).Nanoseconds() / int64(time.Millisecond))

	deltaStat.RxByteRate = (rxByteDelta * 1000) / timeDeltaMs
	deltaStat.RxPacketRate = (rxPktDelta * 1000) / timeDeltaMs
	deltaStat.RxDropRate = float64(rxDropDelta * 1000) / float64(timeDeltaMs)
	deltaStat.RxErrorRate = float64(rxErrorDelta * 1000) / float64(timeDeltaMs)
	deltaStat.TxByteRate = (txByteDelta * 1000) / timeDeltaMs
	deltaStat.TxPacketRate = (txPktDelta * 1000) / timeDeltaMs
	deltaStat.TxDropRate = float64(txDropDelta * 1000) / float64(timeDeltaMs)
	deltaStat.TxErrorRate = float64(txErrorDelta * 1000) / float64(timeDeltaMs)

	return deltaStat
}

func GetNetInterfaces(cg Cgroup) ([]string, error) {
	lines, err := procNetDevLines(cg)
	if err != nil {
		return make([]string, 0), err
	}

	return getNetInterfacesRaw(lines)
}

func getNetInterfacesRaw(lines []string) ([]string, error) {
	nets := make([]string, 0, 4)

	for i := range lines {
		fields := strings.Fields(lines[i])
		if !strings.HasSuffix(fields[0], ":") {
			continue
		}

		nets = append(nets, fields[0][:len(fields[0])-1])
	}

	return nets, nil
}

func GetNetStats(cg Cgroup, intf string) (NetStat, error) {
	var stats NetStat

	err := populateNetStats(cg, intf, &stats)
	if err != nil {
		return stats, err
	}

	return stats, nil
}

func GetNetItemizedStats(cg Cgroup) (NetItemizedStats, error) {
	var stats NetItemizedStats
	stats.Stats = make(map[string]NetStat)

	lines, err := procNetDevLines(cg)
	if err != nil {
		return stats, err
	}

	devs, err := getNetInterfacesRaw(lines)
	if err != nil {
		return stats, err
	}

	for i := range devs {
		var stat NetStat
		err = populateNetStatsRaw(devs[i], lines, &stat)
		if err != nil {
			continue
		}
		stats.Stats[devs[i]] = stat
	}

	return stats, nil
}

func populateNetStats(cg Cgroup, intf string, stat *NetStat) error {
	lines, err := procNetDevLines(cg)
	if err != nil {
		return err
	}

	return populateNetStatsRaw(intf, lines, stat)
}

func populateNetStatsRaw(intf string, lines []string, stat *NetStat) error {
	counts := make([]uint64, 0, 20)

	stat.SampleTime = time.Now()

	for i := range lines {
		fields := strings.Fields(lines[i])
		if !strings.HasSuffix(fields[0], ":") {
			continue
		}

		net := fields[0][:len(fields[0])-1]

		if intf != "" && net != intf {
			continue
		}

		if intf == "" && net == "lo" {
			continue
		}

		for idx := 1; idx < len(fields); idx++ {
			value, err := strconv.ParseUint(fields[idx], 10, 64)
			if err != nil {
				continue
			}
			if len(counts) < idx {
				counts = append(counts, value)
			} else {
				counts[idx-1] += value
			}
		}
	}

	v := reflect.ValueOf(stat).Elem()
	for i := 0; i < v.NumField(); i++ {
		tag := v.Type().Field(i).Tag

		statFieldRaw := tag.Get("field")
		if statFieldRaw == "" {
			continue
		}

		statField, err := strconv.ParseInt(statFieldRaw, 10, 32)
		if err != nil {
			return err
		}

		if len(counts) <= int(statField) {
			continue
		}

		v.Field(i).SetUint(counts[statField])
	}

	return nil
}

func procNetDevLines(cg Cgroup) ([]string, error) {
	lines := make([]string, 0, 4)

	pids, err := GetProcs(cg)
	if err != nil || len(pids) < 1 {
		return lines, err
	}

	pid := strconv.Itoa(pids[0])

	fd, err := os.Open(path.Join("/proc", pid, "net/dev"))
	if err != nil {
		return lines, err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		str := strings.TrimSpace(scanner.Text())
		lines = append(lines, str)
	}

	return lines, nil
}
