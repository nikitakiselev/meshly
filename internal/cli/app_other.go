//go:build !linux

package cli

import (
	"fmt"
	"os"
)

// NewApp on non-Linux systems supports only commands that do not touch
// the network stack (help, version).
func NewApp() *App {
	return &App{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin}
}

func init() {
	unsupported = func(name string) error {
		switch name {
		case "help", "version":
			return nil
		}
		return fmt.Errorf("meshly manages Linux kernel networking and runs only on Linux")
	}
}
