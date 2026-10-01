//go:build windows

package main

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

type windowsAgentService struct{}

func platformService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		os.Exit(1)
	}
	if !isService {
		return false
	}
	if svc.Run("NorthGateRMMAgent", windowsAgentService{}) != nil {
		os.Exit(1)
	}
	return true
}

func (windowsAgentService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	log, err := eventlog.Open("NorthGateRMMAgent")
	if err != nil {
		return true, 1
	}
	defer log.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- execute(ctx, os.Args[1:], windowsEventWriter{log}) }()
	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- status
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
				statuses <- status
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

// The agent logger upstream emits only its bounded closed-schema events.
type windowsEventWriter struct{ log *eventlog.Log }

func (writer windowsEventWriter) Write(raw []byte) (int, error) {
	if err := writer.log.Info(1, string(raw)); err != nil {
		return 0, err
	}
	return len(raw), nil
}
