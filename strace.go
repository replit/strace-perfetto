package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type Strace struct {
	DefaultArgs []string
	UserArgs    []string
	Timeout     time.Duration
}

func (s Strace) Run() {
	args := append(s.DefaultArgs, s.UserArgs...)

	ctx := context.Background()
	if s.Timeout != time.Duration(0) {
		var cancel func()
		ctx, cancel = context.WithTimeout(context.Background(), s.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, "strace", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); errors.Is(err, context.Canceled) {
		fmt.Printf("[!] Strace timeout reached: %s\n", err)
	}
}
