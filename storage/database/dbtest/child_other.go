//go:build !linux

package dbtest

import "os/exec"

func configureChild(command *exec.Cmd) {}
