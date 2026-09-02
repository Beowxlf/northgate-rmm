// Command northgate-rmm-agent runs the bounded outbound-only Linux inventory
// agent. Deployment remains prohibited until a separate G2 authorization.
package main

import (
	"context"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	agentcore "github.com/Beowxlf/northgate-rmm/agent"
	"github.com/Beowxlf/northgate-rmm/agent/collector"
	"github.com/Beowxlf/northgate-rmm/agent/config"
	"github.com/Beowxlf/northgate-rmm/agent/eventlog"
	"github.com/Beowxlf/northgate-rmm/agent/identity"
	agentruntime "github.com/Beowxlf/northgate-rmm/agent/runtime"
	"github.com/Beowxlf/northgate-rmm/agent/sequence"
	"github.com/Beowxlf/northgate-rmm/agent/spool"
	"github.com/Beowxlf/northgate-rmm/agent/transport"
)

var version = "0.2.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(execute(ctx, os.Args[1:], os.Stdout))
}

func execute(ctx context.Context, args []string, output io.Writer) int {
	flags := flag.NewFlagSet("northgate-rmm-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "")
	showVersion := flags.Bool("version", false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *showVersion {
		if *configPath != "" || len(args) != 1 {
			return 2
		}
		if _, err := io.WriteString(output, version+"\n"); err != nil {
			return 1
		}
		return 0
	}
	if *configPath == "" {
		return 2
	}
	if err := run(ctx, *configPath, output); err != nil {
		emitSetupFailure(output)
		return 1
	}
	return 0
}

func run(ctx context.Context, configPath string, output io.Writer) error {
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	cfg, err := config.Decode(file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}

	loadedIdentity, err := identity.Load(filepath.Join(cfg.StateDirectory, "identity"), time.Now())
	if err != nil || loadedIdentity.EndpointID != cfg.EndpointID {
		return agentruntime.ErrRuntimeFailed
	}
	queue, err := spool.Open(filepath.Join(cfg.StateDirectory, "spool"), cfg.MaxSpoolBytes)
	if err != nil {
		return err
	}
	defer queue.Close()
	sequences, err := sequence.Open(filepath.Join(cfg.StateDirectory, "sequence"))
	if err != nil {
		return err
	}
	defer sequences.Close()
	runner, err := collector.NewRunner(version)
	if err != nil {
		return err
	}
	snapshotter, err := agentcore.NewSnapshotter(runner, queue, sequences)
	if err != nil {
		return err
	}
	sender, err := transport.NewMTLSSender(cfg.ControlPlaneURL, transport.Credentials{
		Certificate: loadedIdentity.Certificate, ServerRoots: loadedIdentity.ServerRoots,
	}, cfg.RequestTimeout)
	if err != nil {
		return err
	}
	logger, err := eventlog.New(output)
	if err != nil {
		return err
	}
	runtime, err := agentruntime.New(agentruntime.Options{
		EndpointID: cfg.EndpointID, CollectionInterval: cfg.CollectionInterval,
		RequestTimeout: cfg.RequestTimeout, Snapshotter: snapshotter, Queue: queue,
		Sender: sender, Source: collector.NativeSource{}, Logger: logger,
		RetryPolicy: transport.RetryPolicy{
			MaxAttempts: 3, InitialDelay: time.Second, MaximumDelay: 5 * time.Second,
		},
	})
	if err != nil {
		return err
	}
	return runtime.Run(ctx)
}

func emitSetupFailure(output io.Writer) {
	logger, err := eventlog.New(output)
	if err != nil {
		return
	}
	_ = logger.Emit(eventlog.Event{
		Level: eventlog.LevelError, Code: eventlog.CodeAgentLifecycle,
		Component: eventlog.ComponentAgent, Outcome: eventlog.OutcomeFailed,
		FailureClass: eventlog.FailureInternal,
	})
}
