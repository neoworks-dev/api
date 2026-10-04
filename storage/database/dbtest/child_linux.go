//go:build linux

package dbtest

import (
	"os/exec"
	"syscall"
)

// configureChild makes the kernel kill the server when the test process exits.
func configureChild(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
