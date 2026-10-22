package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shenli/keyradar/internal/cli"
	"github.com/shenli/keyradar/internal/tui"
)

func main() { os.Exit(run()) }
func run() (code int) {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "keyradar: internal error (details suppressed to protect credentials)")
			code = 1
		}
	}()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, tui.Run)
}
