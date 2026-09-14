package main

import (
	"context"
	"github.com/Beowxlf/northgate-rmm/agent/management"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if platformService() {
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(execute(ctx, os.Args[1:]))
}
func execute(ctx context.Context, args []string) int {
	if len(args) == 1 && args[0] == "--version" {
		_, _ = os.Stdout.WriteString(management.Version + "\n")
		return 0
	}
	if len(args) == 2 && args[0] == "--release-isolation" {
		if management.ReleaseIsolation(ctx, args[1]) != nil {
			return 1
		}
		return 0
	}
	if len(args) == 2 && args[0] == "--apply-update" {
		if management.ApplyUpdate(ctx, args[1]) != nil {
			return 1
		}
		return 0
	}
	if len(args) != 2 || args[0] != "--config" {
		return 2
	}
	if management.Run(ctx, args[1]) != nil {
		return 1
	}
	return 0
}
