//go:build linux

package management

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

//go:embed linux_actions.py
var linuxActions string

func defaultConfig() string { return "/etc/northgate-rmm-management/config.json" }
func requirePrivileged() error {
	if os.Geteuid() != 0 {
		return errors.New("management worker requires root")
	}
	return nil
}
func executionIdentity() string { return "root (uid=0)" }
func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}
func captureInstalled() bool {
	_, e := os.Stat("/usr/local/libexec/northgate-wxlfgar/wulfgar")
	return e == nil
}
func platformRecoveryStatus() map[string]any {
	return map[string]any{"managed_account": "ng-rmm-recovery", "status": "query recovery metadata"}
}
func platformCapabilities() map[string]any {
	m := map[string]any{"shell": true, "files": true, "services": true, "processes": true, "logs": true, "posture": true, "recovery": true, "bitlocker": false}
	for k, p := range map[string]string{"packages": "/usr/bin/apt-get", "isolation": "/usr/sbin/nft", "python": "/usr/bin/python3"} {
		_, e := os.Stat(p)
		m[k] = e == nil
	}
	return m
}
func validateWorkerPaths(path string, c Config) error {
	for _, p := range []string{path, c.Roots, filepath.Dir(path)} {
		i, e := os.Lstat(p)
		if e != nil {
			return e
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || i.Mode().Perm()&0022 != 0 || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("configuration must be root-owned and not writable by others")
		}
	}
	if i, e := os.Lstat(c.Root); e == nil {
		if s := i.Sys().(*syscall.Stat_t); s.Uid != 0 || i.Mode().Perm()&0077 != 0 || !i.IsDir() {
			return errors.New("unsafe worker root")
		}
	}
	return nil
}
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
func scriptCommand(ctx context.Context, path string) *exec.Cmd {
	return exec.CommandContext(ctx, "/bin/bash", "--noprofile", "--norc", path)
}
func platformAction(ctx context.Context, j Job, c Config) Result {
	binary, _ := os.Executable()
	v := map[string]any{"action": j.Action, "params": j.Params, "root": c.Root, "server_ip": c.ServerIP, "job": j.ID, "binary": binary, "config": defaultConfig()}
	b, _ := json.Marshal(v)
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", linuxActions)
	cmd.Stdin = strings.NewReader(string(b))
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "DEBIAN_FRONTEND=noninteractive"}
	return runCommand(ctx, cmd, MaxOutput)
}

type linuxTerminal struct {
	file    *os.File
	cmd     *exec.Cmd
	once    sync.Once
	wait    sync.Once
	waitErr error
}

func openTerminal(ctx context.Context, columns, rows int) (terminal, error) {
	fd, e := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	master := os.NewFile(uintptr(fd), "management-pty")
	if e = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); e != nil {
		master.Close()
		return nil, e
	}
	number, e := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if e != nil {
		master.Close()
		return nil, e
	}
	slave, e := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if e != nil {
		master.Close()
		return nil, e
	}
	cmd := exec.CommandContext(ctx, "/bin/bash", "--noprofile", "--norc", "-i")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "PS1=NorthGate root\\$ ")
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	t := &linuxTerminal{file: master, cmd: cmd}
	if e = t.Resize(columns, rows); e == nil {
		e = cmd.Start()
	}
	slave.Close()
	if e != nil {
		master.Close()
		return nil, e
	}
	return t, nil
}
func (t *linuxTerminal) Read(b []byte) (int, error) {
	n, e := t.file.Read(b)
	if errors.Is(e, syscall.EIO) {
		e = io.EOF
	}
	return n, e
}
func (t *linuxTerminal) Write(b []byte) (int, error) { return t.file.Write(b) }
func (t *linuxTerminal) Resize(c, r int) error {
	return unix.IoctlSetWinsize(int(t.file.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(c), Row: uint16(r)})
}
func (t *linuxTerminal) Close() error {
	t.once.Do(func() {
		if t.cmd.Process != nil {
			terminateTerminalSession(t.cmd.Process.Pid)
		}
		t.file.Close()
	})
	return nil
}
func terminateTerminalSession(session int) {
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid < 2 {
			continue
		}
		fd, e := unix.PidfdOpen(pid, 0)
		if e != nil {
			continue
		}
		raw, e := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if e == nil {
			line := string(raw)
			end := strings.LastIndex(line, ") ")
			if end >= 0 {
				fields := strings.Fields(line[end+2:])
				if len(fields) > 3 && fields[3] == strconv.Itoa(session) {
					_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
				}
			}
		}
		unix.Close(fd)
	}
	_ = syscall.Kill(-session, syscall.SIGKILL)
}
func (t *linuxTerminal) Wait() error {
	t.wait.Do(func() { t.waitErr = t.cmd.Wait() })
	return t.waitErr
}
func scheduleUpdate(ctx context.Context, j Job, c Config, path string) Result {
	return platformScheduleUpdate(ctx, j, c, path)
}
