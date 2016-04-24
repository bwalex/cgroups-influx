package cgroups

import (
	"bufio"
	"os"
	"path"
	"strings"
	"sync"
)

var blockDeviceCache struct {
	sync.Mutex
	cache map[string]string
}

const (
	SysDevBlockRoot = "/sys/dev/block"
)

func GetBlockDeviceFromMajMin(majMin string) string {
	blockDeviceCache.Lock()
	defer blockDeviceCache.Unlock()

	if dev, ok := blockDeviceCache.cache[majMin]; ok {
		return dev
	}

	fd, err := os.Open(path.Join(SysDevBlockRoot, majMin, "uevent"))
	if err != nil {
		return majMin
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		parts := strings.Split(strings.TrimSpace(scanner.Text()), "=")
		if strings.ToLower(parts[0]) != "devtype" {
			continue
		}

		blockDeviceCache.cache[majMin] = parts[1]

		return parts[1]
	}

	return majMin
}
