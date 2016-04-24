package cgroups

import (
	"bufio"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type MemoryStat struct {
	// From memory.stat
	Cache              uint64 `stat:"cache"`
	RSS                uint64 `stat:"rss"`
	RSSHuge            uint64 `stat:"rss_huge"`
	PgFault            uint64 `stat:"pgfault"`
	PgMajFault         uint64 `stat:"pgmajfault"`
	Swap               uint64 `stat:"swap"`
	MappedFile         uint64 `stat:"mapped_file"`
	Unevictable        uint64 `stat:"unevictable"`
	InactiveAnon       uint64 `stat:"inactive_anon"`
	ActiveAnon         uint64 `stat:"active_anon"`
	InactiveFile       uint64 `stat:"inactive_file"`
	ActiveFile         uint64 `stat:"active_file"`

	TotalCache         uint64 `stat:"total_cache"`
	TotalRSS           uint64 `stat:"total_rss"`
	TotalRSSHuge       uint64 `stat:"total_rss_huge"`
	TotalPgFault       uint64 `stat:"total_pgfault"`
	TotalPgMajFault    uint64 `stat:"total_pgmajfault"`
	TotalSwap          uint64 `stat:"total_swap"`
	TotalMappedFile    uint64 `stat:"total_mapped_file"`
	TotalUnevictable   uint64 `stat:"total_unevictable"`
	TotalInactiveAnon  uint64 `stat:"total_inactive_anon"`
	TotalActiveAnon    uint64 `stat:"total_active_anon"`
	TotalInactiveFile  uint64 `stat:"total_inactive_file"`
	TotalActiveFile    uint64 `stat:"total_active_file"`

	// From other files
	MemUsage           uint64 `file:"memory.usage_in_bytes"`
	MemUsageMax        uint64 `file:"memory.max_usage_in_bytes"`
	MemFailCnt         uint64 `file:"memory.failcnt"`
	MemLimit           uint64 `file:"memory.limit_in_bytes"`
	MemSwapUsage       uint64 `file:"memory.memsw.usage_in_bytes"`
	MemSwapUsageMax    uint64 `file:"memory.memsw.max_usage_in_bytes"`
	MemSwapFailCnt     uint64 `file:"memory.memsw.failcnt"`
	MemSwapLimit       uint64 `file:"memory.memsw.limit_in_bytes"`
	KMemUsage          uint64 `file:"memory.kmem.usage_in_bytes"`
	KMemUsageMax       uint64 `file:"memory.kmem.max_usage_in_bytes"`
	KMemFailCnt        uint64 `file:"memory.kmem.failcnt"`
	KMemLimit          uint64 `file:"memory.kmem.limit_in_bytes"`

	SampleTime         time.Time
}

const (
	ControllerMemory = "memory"
)

func populateMemoryStat(cg Cgroup, stat *MemoryStat) error {
	path, err := GetCgroupPath(cg, ControllerMemory, "memory.stat")
	if err == ErrNoCgroup {
		return err
	}

	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()

	rawStats := make(map[string]uint64)

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}

		rawStats[parts[0]] = value
	}

	v := reflect.ValueOf(stat).Elem()

	for i := 0; i < v.NumField(); i++ {
		tag := v.Type().Field(i).Tag

		stat_name := tag.Get("stat")
		if stat_name == "" {
			continue
		}

		if value, found := rawStats[stat_name]; found {
			v.Field(i).SetUint(value)
		}
	}

	return nil
}

func populateMemoryOther(cg Cgroup, stat *MemoryStat) error {
	v := reflect.ValueOf(stat).Elem()
	for i := 0; i < v.NumField(); i++ {
		tag := v.Type().Field(i).Tag

		fileName := tag.Get("file")
		if fileName == "" {
			continue
		}

		path, err := GetCgroupPath(cg, ControllerMemory, fileName)
		if err == ErrNoCgroup {
			return err
		}

		contentsRaw, err := ioutil.ReadFile(path)
		if err != nil {
			continue
		}

		contents := strings.TrimSpace(string(contentsRaw))
		value, err := strconv.ParseUint(contents, 10, 64)
		if err != nil {
			continue
		}

		v.Field(i).SetUint(value)
	}

	return nil
}

func GetMemoryStats(cg Cgroup) (MemoryStat, error) {
	var stats MemoryStat

	stats.SampleTime = time.Now()

	err := populateMemoryStat(cg, &stats)
	if err != nil {
		return stats, err
	}

	err = populateMemoryOther(cg, &stats)
	if err != nil {
		return stats, err
	}

	return stats, nil
}
