//go:build !windows

// Package sockopt holds the socket options UDP broadcast listeners need.
package sockopt

import "syscall"

// ReuseAndBroadcast lets a socket share its port and send broadcasts.
func ReuseAndBroadcast(fd uintptr) error {
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}
