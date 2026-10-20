// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-meta/internal/messengercli"
)

func main() {
	os.Exit(mainCode())
}

func mainCode() (code int) {
	// Keep protocol logs disabled for the entire executable lifetime, including
	// any upstream background callbacks during shutdown.
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer func() {
		if recover() != nil {
			// Upstream panic values may contain private protocol data.
			fmt.Fprintln(os.Stderr, "Messenger CLI stopped unexpectedly; no diagnostic payload was printed.")
			code = 1
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := messengercli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}
