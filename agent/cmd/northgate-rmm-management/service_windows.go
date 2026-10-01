//go:build windows

package main

import (
	"context"
	"golang.org/x/sys/windows/svc"
	"os"
	"time"
)

type handler struct{}

func platformService() bool {
	yes, e := svc.IsWindowsService()
	if e != nil {
		os.Exit(1)
	}
	if !yes {
		return false
	}
	if svc.Run("NorthGateRMMManagement", handler{}) != nil {
		os.Exit(1)
	}
	return true
}
func (handler) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- execute(ctx, os.Args[1:]) }()
	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- current
	for {
		select {
		case code := <-done:
			return code != 0, uint32(code)
		case request, ok := <-requests:
			if !ok {
				cancel()
				return true, 1
			}
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- current
			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending, WaitHint: 15000}
				cancel()
				select {
				case code := <-done:
					return code != 0, uint32(code)
				case <-time.After(15 * time.Second):
					return true, 1
				}
			}
		}
	}
}
