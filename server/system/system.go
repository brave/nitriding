package system

import (
	"errors"
	"fmt"
	"syscall"
)

const (
	ErrMaxFdLimitLowerThanSoft = "hard file descriptor limit cannot be lower" +
		" than the soft limit"
	ErrGetFdLimit = "cannot get the current file descriptor limit"
	ErrSetFdLimit = "cannot set file descriptor limit"
)

const LocalHostAddr = "127.0.0.1"

const (
	DefaultFdSoft = uint64(65535)
	DefaultFdHard = uint64(65535)
)

func SetFdLimit(soft, hard uint64) error {
	if soft == 0 {
		soft = DefaultFdSoft
	}
	if hard == 0 {
		hard = DefaultFdHard
	}

	if hard < soft {
		return errors.New(ErrMaxFdLimitLowerThanSoft)
	}

	var rLimit = new(syscall.Rlimit)
	rLimit.Cur, rLimit.Max = soft, hard
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, rLimit); err != nil {
		return fmt.Errorf("%v: %w", ErrSetFdLimit, err)
	}

	return nil
}

func GetFdLimit() (uint64, uint64, error) {
	var rLimit = new(syscall.Rlimit)

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, rLimit); err != nil {
		return 0, 0, fmt.Errorf("%v: %w", ErrGetFdLimit, err)
	}

	return rLimit.Cur, rLimit.Max, nil
}
