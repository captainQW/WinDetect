package winutil

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// PSTimeout is the default timeout for a single PowerShell invocation.
const PSTimeout = 25 * time.Second

// RunPS runs a PowerShell script and returns trimmed stdout.
// It hides the console window and applies a timeout so a hung
// command can never block an API request indefinitely.
func RunPS(script string) (string, error) {
	return RunPSTimeout(script, PSTimeout)
}

// RunPSTimeout is RunPS with a caller supplied timeout.
func RunPSTimeout(script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", script)
	hideWindow(cmd)

	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		// Prefer surfacing stderr text when available.
		if errBuf.Len() > 0 {
			return strings.TrimSpace(out.String()), &PSError{Stderr: strings.TrimSpace(errBuf.String()), Err: err}
		}
		return strings.TrimSpace(out.String()), err
	}
	return strings.TrimSpace(out.String()), nil
}

// RunPSJSON runs a script and unmarshals the JSON stdout into v.
// PowerShell emits a single object (not an array) when only one row
// is returned, so callers should accept both shapes where relevant.
func RunPSJSON(script string, v interface{}) error {
	out, err := RunPS(script)
	if err != nil && out == "" {
		return err
	}
	if strings.TrimSpace(out) == "" {
		return nil
	}
	return json.Unmarshal([]byte(out), v)
}

// RunPSJSONTimeout is RunPSJSON with a caller supplied timeout, for scripts
// that do heavier work (e.g. batched Authenticode signature checks).
func RunPSJSONTimeout(script string, timeout time.Duration, v interface{}) error {
	out, err := RunPSTimeout(script, timeout)
	if err != nil && out == "" {
		return err
	}
	if strings.TrimSpace(out) == "" {
		return nil
	}
	return json.Unmarshal([]byte(out), v)
}

// PSError wraps a PowerShell failure with its stderr text.
type PSError struct {
	Stderr string
	Err    error
}

func (e *PSError) Error() string {
	if e.Stderr != "" {
		return e.Stderr
	}
	return e.Err.Error()
}

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
