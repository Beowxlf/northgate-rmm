package main

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/config"
	"github.com/Beowxlf/northgate-rmm/agent/identity"
	"github.com/Beowxlf/northgate-rmm/agent/transport"
)

func enroll(ctx context.Context, configPath, origin, grantPath, serverRootsPath, issuerRootsPath string) error {
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	cfg, decodeErr := config.Decode(file)
	closeErr := file.Close()
	if decodeErr != nil || closeErr != nil {
		return transport.ErrEnrollment
	}
	if err := validatePlatformState(cfg.StateDirectory); err != nil {
		return err
	}
	directory := filepath.Join(cfg.StateDirectory, "identity")
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		return transport.ErrEnrollment
	}
	grant, err := boundedEnrollmentFile(grantPath, 128, true)
	if err != nil {
		return err
	}
	serverRoots, err := boundedEnrollmentFile(serverRootsPath, 65536, false)
	if err != nil {
		return err
	}
	issuerRoots, err := boundedEnrollmentFile(issuerRootsPath, 65536, false)
	if err != nil {
		return err
	}
	expectedID := cfg.EndpointID
	if expectedID == bootstrapEndpointID {
		expectedID = ""
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(serverRoots) {
		return transport.ErrEnrollment
	}
	verify, err := transport.StatusVerifier(cfg.ServerStatusURL, []byte(cfg.ServerStatusPublicKey), roots)
	if err != nil {
		return err
	}
	material, err := transport.Enroll(ctx, origin, strings.TrimSpace(string(grant)), expectedID, serverRoots, issuerRoots, cfg.RequestTimeout, verify)
	if err != nil {
		return err
	}
	return identity.Install(directory, material, time.Now())
}

func boundedEnrollmentFile(name string, maximum int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(name) {
		return nil, transport.ErrEnrollment
	}
	before, err := os.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, transport.ErrEnrollment
	}
	if private && validatePrivateInput(name, before) != nil {
		return nil, transport.ErrEnrollment
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, transport.ErrEnrollment
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, transport.ErrEnrollment
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, transport.ErrEnrollment
	}
	return raw, nil
}
