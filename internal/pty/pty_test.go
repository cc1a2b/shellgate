package pty

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requirePTY skips the test if PTY allocation is not available (e.g., in sandboxed environments).
func requirePTY(t *testing.T) {
	t.Helper()
	sess, err := New("/bin/sh", nil)
	if err != nil {
		t.Skipf("PTY not available in this environment: %v", err)
	}
	sess.Close()
}

func TestNew(t *testing.T) {
	requirePTY(t)

	sess, err := New("/bin/sh", nil)
	require.NoError(t, err)
	defer sess.Close()

	assert.NotNil(t, sess.ptmx)
	assert.NotNil(t, sess.cmd)
	assert.NotNil(t, sess.cmd.Process)
}

func TestNewInvalidShell(t *testing.T) {
	_, err := New("/nonexistent/shell", nil)
	assert.Error(t, err)
}

func TestReadWrite(t *testing.T) {
	requirePTY(t)

	sess, err := New("/bin/sh", nil)
	require.NoError(t, err)
	defer sess.Close()

	// Write a command
	cmd := "echo shellgate_test_marker\n"
	n, err := sess.Write([]byte(cmd))
	require.NoError(t, err)
	assert.Equal(t, len(cmd), n)

	// Read output — may need multiple reads
	buf := make([]byte, 4096)
	var output []byte
	deadline := time.After(3 * time.Second)

	for {
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for output, got: %q", string(output))
		default:
		}

		n, err := sess.Read(buf)
		if n > 0 {
			output = append(output, buf[:n]...)
		}
		if err != nil {
			break
		}
		if containsBytes(output, []byte("shellgate_test_marker")) {
			break
		}
	}

	assert.Contains(t, string(output), "shellgate_test_marker")
}

func TestResize(t *testing.T) {
	requirePTY(t)

	sess, err := New("/bin/sh", nil)
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Resize(120, 40)
	assert.NoError(t, err)

	err = sess.Resize(80, 24)
	assert.NoError(t, err)
}

func TestDone(t *testing.T) {
	requirePTY(t)

	sess, err := New("/bin/sh", nil)
	require.NoError(t, err)

	// Send exit to the shell
	_, err = sess.Write([]byte("exit\n"))
	require.NoError(t, err)

	select {
	case <-sess.Done():
		// Process exited successfully
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for shell to exit")
	}

	sess.Close()
}

func TestClose(t *testing.T) {
	requirePTY(t)

	sess, err := New("/bin/sh", nil)
	require.NoError(t, err)

	err = sess.Close()
	assert.NoError(t, err)

	// Subsequent writes should fail
	_, err = sess.Write([]byte("test"))
	assert.Error(t, err)
}

func TestBuildEnv(t *testing.T) {
	env := buildEnv([]string{"CUSTOM=value"})
	assert.NotEmpty(t, env)

	found := false
	for _, e := range env {
		if e == "CUSTOM=value" {
			found = true
		}
	}
	assert.True(t, found, "custom env var should be in environment")

	// Check mandatory vars exist
	hasTermVar := false
	for _, e := range env {
		if len(e) > 5 && e[:5] == "TERM=" {
			hasTermVar = true
		}
	}
	assert.True(t, hasTermVar, "TERM should be set")
}

func containsBytes(haystack, needle []byte) bool {
	return len(haystack) >= len(needle) && bytesContains(haystack, needle)
}

func bytesContains(b, sub []byte) bool {
	for i := 0; i <= len(b)-len(sub); i++ {
		if bytesEqual(b[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
