//go:build !windows && !linux

package main

import (
	"errors"
	"time"
)

func runReflect(string, int, time.Duration) error {
	return errors.New("reflect needs Windows and Npcap")
}
