// Package sockopt holds the socket options UDP broadcast listeners need.
package sockopt

import "golang.org/x/sys/windows"

// ReuseAndBroadcast lets a socket share its port with others (the Windows DHCP
// Client on port 68, or a second instance of this app) and send broadcasts.
func ReuseAndBroadcast(fd uintptr) error {
	h := windows.Handle(fd)
	if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_REUSEADDR, 1); err != nil {
		return err
	}
	return windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
}
