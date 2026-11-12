//go:build !linux

package main

import (
	"errors"
	"time"
)

func runLoopCable(string, string, int, time.Duration) error {
	return errors.New("loopcable needs Linux")
}
