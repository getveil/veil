//go:build darwin

package runner

import "syscall"

func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
	}
}
