//go:build !linux

package brutal

import (
	"errors"
)

func IsLoaded() bool {
	return false
}

func Load() error {
	return errors.ErrUnsupported
}

func LoadWithOptions(opts Options) error {
	return errors.ErrUnsupported
}

func Unload() error {
	return errors.ErrUnsupported
}

func UnloadWithOptions(opts Options) error {
	return errors.ErrUnsupported
}

type Options struct {
	CgroupPath string
	Force      bool
}

func (opts Options) Load() error {
	return errors.ErrUnsupported
}

func (opts Options) Unload() error {
	return errors.ErrUnsupported
}
