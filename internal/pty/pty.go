// Package pty provides pseudo-terminal allocation and management for ShellGate.
package pty

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

// Session represents an active PTY session with a running shell process.
type Session struct {
	cmd  *exec.Cmd
	ptmx *os.File
	mu   sync.Mutex
	done chan struct{}
}

// New allocates a new PTY and spawns the given shell command.
// The shell runs with a clean environment inheriting only essential variables.
func New(shell string, envVars []string) (*Session, error) {
	cmd := exec.Command(shell)

	// Build a clean environment
	cmd.Env = buildEnv(envVars)

	// Set process group so we can kill the entire tree on cleanup
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("pty start: %w", err)
	}

	s := &Session{
		cmd:  cmd,
		ptmx: ptmx,
		done: make(chan struct{}),
	}

	// Wait for the process in a goroutine and signal when done
	go func() {
		_ = cmd.Wait()
		close(s.done)
	}()

	return s, nil
}

// Read reads output from the PTY.
func (s *Session) Read(p []byte) (int, error) {
	n, err := s.ptmx.Read(p)
	if err != nil {
		return n, fmt.Errorf("pty read: %w", err)
	}
	return n, nil
}

// Write sends input to the PTY.
func (s *Session) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, err := s.ptmx.Write(p)
	if err != nil {
		return n, fmt.Errorf("pty write: %w", err)
	}
	return n, nil
}

// Resize changes the PTY window size.
func (s *Session) Resize(cols, rows uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := pty.Setsize(s.ptmx, &pty.Winsize{
		Cols: cols,
		Rows: rows,
	}); err != nil {
		return fmt.Errorf("pty resize: %w", err)
	}
	return nil
}

// Done returns a channel that is closed when the shell process exits.
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// Close terminates the PTY session, killing the process group and closing the fd.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error

	// Kill the entire process group
	if s.cmd.Process != nil {
		pgid, err := syscall.Getpgid(s.cmd.Process.Pid)
		if err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		} else {
			_ = s.cmd.Process.Kill()
		}
	}

	// Close the PTY fd
	if err := s.ptmx.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("pty close: %w", err)
	}

	return firstErr
}

// WriteTo implements io.WriterTo for efficient copying from PTY to a writer.
func (s *Session) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, s.ptmx)
}

// buildEnv creates a clean environment for the shell process.
func buildEnv(extra []string) []string {
	env := []string{
		"TERM=xterm-256color",
		"LANG=" + getEnvOrDefault("LANG", "en_US.UTF-8"),
		"HOME=" + getEnvOrDefault("HOME", "/root"),
		"USER=" + getEnvOrDefault("USER", "root"),
		"SHELL=" + getEnvOrDefault("SHELL", "/bin/bash"),
		"PATH=" + getEnvOrDefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
	}
	env = append(env, extra...)
	return env
}

func getEnvOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
