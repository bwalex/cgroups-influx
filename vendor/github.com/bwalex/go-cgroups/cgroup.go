package cgroups

import (
	"errors"
	"os"
	"path"
)

type Cgroup struct {
	Root      string // defaults to: DefaultSysfsRoot
	Cgroup    string // e.g.: /machine.slice/foo.service
}

const (
	DefaultSysfsRoot = "/sys/fs/cgroup"
)

var (
	ErrNoCgroup = errors.New("go-cgroups: Could not find path to cgroup")
	ErrNoStat   = errors.New("go-cgroups: Could not find cgroup stat file")
)

func GetCgroupPath(cg Cgroup, controller string, file string) (string, error) {
	cgDir := ""
	root := cg.Root
	if root == "" {
		root = DefaultSysfsRoot
	}

	guesses := make([]string, 0, 5)
	guesses = append(guesses, path.Join(root, controller, cg.Cgroup))
	guesses = append(guesses, path.Join(root, cg.Cgroup))

	for i := range guesses {
		if _, err := os.Stat(guesses[i]); err != nil {
			continue
		}

		cgDir = guesses[i]
		break
	}

	if cgDir == "" {
		return "", ErrNoCgroup
	}

	if file == "" {
		return cgDir, nil
	}

	return path.Join(cgDir, file), nil
}
