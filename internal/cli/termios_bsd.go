//go:build darwin || freebsd

package cli

import "golang.org/x/sys/unix"

const ioctlGetTermios = unix.TIOCGETA
