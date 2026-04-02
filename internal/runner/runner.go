package runner

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Result holds the outcome of a command execution.
type Result struct {
	Success  bool
	Stdout   string
	Stderr   string
	Duration time.Duration
	Err      error
}

// Run executes a command with the given context and timeout.
// It never uses shell=true — always direct exec.
func Run(ctx context.Context, cmd []string, timeout time.Duration) Result {
	if len(cmd) == 0 {
		return Result{Err: fmt.Errorf("empty command")}
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	start := time.Now()

	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)

	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()
	duration := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		slog.Warn("command timed out",
			"cmd", cmd[0],
			"timeout", timeout,
			"duration", duration,
		)
		return Result{
			Stderr:   stderr.String(),
			Duration: duration,
			Err:      fmt.Errorf("command timed out after %s", timeout),
		}
	}

	if err != nil {
		return Result{
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			Duration: duration,
			Err:      err,
		}
	}

	return Result{
		Success:  true,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: duration,
	}
}

// RunToFile executes a command and writes stdout to a file.
func RunToFile(ctx context.Context, cmd []string, outputFile string, timeout time.Duration) Result {
	if len(cmd) == 0 {
		return Result{Err: fmt.Errorf("empty command")}
	}

	// Ensure output directory exists
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Result{Err: fmt.Errorf("creating output dir: %w", err)}
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	start := time.Now()

	f, err := os.Create(outputFile)
	if err != nil {
		return Result{Err: fmt.Errorf("creating output file: %w", err)}
	}
	defer f.Close()

	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)

	var stderr bytes.Buffer
	c.Stdout = f
	c.Stderr = &stderr

	err = c.Run()
	duration := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		slog.Warn("command timed out",
			"cmd", cmd[0],
			"output_file", outputFile,
			"timeout", timeout,
		)
		return Result{
			Stderr:   stderr.String(),
			Duration: duration,
			Err:      fmt.Errorf("command timed out after %s", timeout),
		}
	}

	if err != nil {
		return Result{
			Stderr:   stderr.String(),
			Duration: duration,
			Err:      err,
		}
	}

	return Result{
		Success:  true,
		Stderr:   stderr.String(),
		Duration: duration,
	}
}

// RunWithStdin executes a command piping stdinFile as input and writing stdout to outputFile.
func RunWithStdin(ctx context.Context, cmd []string, stdinFile, outputFile string, timeout time.Duration) Result {
	if len(cmd) == 0 {
		return Result{Err: fmt.Errorf("empty command")}
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	start := time.Now()

	inFile, err := os.Open(stdinFile)
	if err != nil {
		return Result{Err: fmt.Errorf("opening stdin file: %w", err)}
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return Result{Err: fmt.Errorf("creating output file: %w", err)}
	}
	defer outFile.Close()

	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)

	var stderr bytes.Buffer
	c.Stdin = inFile
	c.Stdout = outFile
	c.Stderr = &stderr

	err = c.Run()
	duration := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		return Result{
			Stderr:   stderr.String(),
			Duration: duration,
			Err:      fmt.Errorf("command timed out after %s", timeout),
		}
	}

	if err != nil {
		return Result{
			Stderr:   stderr.String(),
			Duration: duration,
			Err:      err,
		}
	}

	return Result{
		Success:  true,
		Stderr:   stderr.String(),
		Duration: duration,
	}
}

// RunWithWorkDir executes a command in the given working directory.
func RunWithWorkDir(ctx context.Context, cmd []string, workDir string, timeout time.Duration) Result {
	if len(cmd) == 0 {
		return Result{Err: fmt.Errorf("empty command")}
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	start := time.Now()

	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	c.Dir = workDir

	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()
	duration := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		return Result{
			Stderr:   stderr.String(),
			Duration: duration,
			Err:      fmt.Errorf("command timed out after %s", timeout),
		}
	}

	if err != nil {
		return Result{
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			Duration: duration,
			Err:      err,
		}
	}

	return Result{
		Success:  true,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: duration,
	}
}

// FormatCmd returns a human-readable command string (for logging).
func FormatCmd(cmd []string) string {
	return strings.Join(cmd, " ")
}
