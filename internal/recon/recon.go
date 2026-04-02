package recon

import (
	"bufio"
	"context"
	"fmt"
	"github.com/xalgord/reconx/internal/logger"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/reconx/internal/config"
	"github.com/xalgord/reconx/internal/runner"
)

// Result holds the outcome of a recon phase for a single target.
type Result struct {
	Target         string
	TargetIndex    int
	SubdomainCount int
	LiveHostCount  int
	OutputDir      string
	LiveSubsFile   string
}

// RunRecon performs full recon for a single target:
// 1. Subdomain enumeration (subfinder + findomain + assetfinder in parallel)
// 2. Merge and deduplicate
// 3. DNS resolution with dnsx
func RunRecon(ctx context.Context, cfg *config.Config, target string, targetIndex, totalTargets int) (*Result, error) {
	// Create target output directory
	safeName := strings.ReplaceAll(target, ".", "_")
	targetDir := filepath.Join(cfg.OutputDir, safeName)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating target dir: %w", err)
	}

	// Run subdomain enumeration tools in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	var outputFiles []string

	type enumTask struct {
		name string
		fn   func() string
	}

	tasks := []enumTask{
		{"subfinder", func() string { return runSubfinder(ctx, cfg, target, targetDir) }},
		{"findomain", func() string { return runFindomain(ctx, cfg, target, targetDir) }},
		{"assetfinder", func() string { return runAssetfinder(ctx, cfg, target, targetDir) }},
	}

	for _, task := range tasks {
		if task.name == "subfinder" && cfg.Tools.Subfinder == "" {
			continue
		}
		if task.name == "findomain" && cfg.Tools.Findomain == "" {
			continue
		}
		if task.name == "assetfinder" && cfg.Tools.Assetfinder == "" {
			continue
		}

		wg.Add(1)
		go func(t enumTask) {
			defer wg.Done()
			outFile := t.fn()
			if outFile != "" {
				mu.Lock()
				outputFiles = append(outputFiles, outFile)
				mu.Unlock()
			}
		}(task)
	}

	wg.Wait()

	// Check context cancellation
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Merge and deduplicate
	allSubsFile := filepath.Join(targetDir, "all_subdomains.txt")
	subCount := mergeSubdomains(outputFiles, allSubsFile)
	logger.Info("subdomain enumeration complete",
		"target", target,
		"subdomains", subCount,
	)

	// DNS resolution
	liveSubsFile := filepath.Join(targetDir, "live_subs.txt")
	liveCount := runDnsxResolve(ctx, cfg, allSubsFile, liveSubsFile)
	logger.Info("DNS resolution complete",
		"target", target,
		"live_hosts", liveCount,
	)

	return &Result{
		Target:         target,
		TargetIndex:    targetIndex,
		SubdomainCount: subCount,
		LiveHostCount:  liveCount,
		OutputDir:      targetDir,
		LiveSubsFile:   liveSubsFile,
	}, nil
}

func runSubfinder(ctx context.Context, cfg *config.Config, target, targetDir string) string {
	outputFile := filepath.Join(targetDir, "subfinder.txt")

	cmd := []string{
		cfg.Tools.Subfinder,
		"-d", target,
		"-all",
		"-recursive",
		"-t", fmt.Sprintf("%d", cfg.Recon.SubfinderThreads),
		"-silent",
		"-o", outputFile,
	}

	logger.Info("running subfinder", "target", target)
	result := runner.Run(ctx, cmd, 30*time.Minute)
	if !result.Success {
		logger.Warn("subfinder error", "target", target, "error", result.Err)
	}
	return outputFile
}

func runFindomain(ctx context.Context, cfg *config.Config, target, targetDir string) string {
	outputFile := filepath.Join(targetDir, "findomain.txt")

	cmd := []string{
		cfg.Tools.Findomain,
		"--quiet",
		"-t", target,
	}

	logger.Info("running findomain", "target", target)
	result := runner.RunToFile(ctx, cmd, outputFile, 20*time.Minute)
	if !result.Success {
		logger.Warn("findomain error", "target", target, "error", result.Err)
	}
	return outputFile
}

func runAssetfinder(ctx context.Context, cfg *config.Config, target, targetDir string) string {
	outputFile := filepath.Join(targetDir, "assetfinder.txt")

	cmd := []string{
		cfg.Tools.Assetfinder,
		"-subs-only",
		target,
	}

	logger.Info("running assetfinder", "target", target)
	result := runner.RunToFile(ctx, cmd, outputFile, 20*time.Minute)
	if !result.Success {
		logger.Warn("assetfinder error", "target", target, "error", result.Err)
	}
	return outputFile
}

func mergeSubdomains(files []string, outputFile string) int {
	seen := make(map[string]bool)

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			sub := strings.TrimSpace(scanner.Text())
			if sub != "" {
				seen[sub] = true
			}
		}
		f.Close()
	}

	// Sort and write
	subs := make([]string, 0, len(seen))
	for sub := range seen {
		subs = append(subs, sub)
	}
	sort.Strings(subs)

	f, err := os.Create(outputFile)
	if err != nil {
		logger.Error("failed to create merged subs file", "error", err)
		return 0
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, sub := range subs {
		writer.WriteString(sub + "\n")
	}
	writer.Flush()

	return len(subs)
}

func runDnsxResolve(ctx context.Context, cfg *config.Config, inputFile, outputFile string) int {
	if cfg.Tools.Dnsx == "" {
		logger.Error("dnsx not found, skipping DNS resolution")
		return 0
	}

	tempFile := outputFile + ".raw"

	cmd := []string{
		cfg.Tools.Dnsx,
		"-l", inputFile,
		"-t", fmt.Sprintf("%d", cfg.DNS.Threads),
		"-rate-limit", fmt.Sprintf("%d", cfg.DNS.RateLimit),
		"-o", tempFile,
	}

	// Add resolvers file if it exists
	if _, err := os.Stat(cfg.DNS.ResolversFile); err == nil {
		cmd = append(cmd, "-r", cfg.DNS.ResolversFile)
	}

	logger.Info("running dnsx resolve")
	result := runner.Run(ctx, cmd, 30*time.Minute)
	if !result.Success {
		logger.Warn("dnsx error", "error", result.Err)
	}

	// Deduplicate the output (replaces shell sort -u)
	count := deduplicateFile(tempFile, outputFile)

	// Clean up temp file
	os.Remove(tempFile)

	return count
}

// deduplicateFile reads lines from inputFile, deduplicates, and writes to outputFile.
// Returns the number of unique lines.
func deduplicateFile(inputFile, outputFile string) int {
	f, err := os.Open(inputFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			seen[line] = true
		}
	}

	lines := make([]string, 0, len(seen))
	for line := range seen {
		lines = append(lines, line)
	}
	sort.Strings(lines)

	out, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	for _, line := range lines {
		writer.WriteString(line + "\n")
	}
	writer.Flush()

	return len(lines)
}

// CountLines counts lines in a file.
func CountLines(filePath string) int {
	f, err := os.Open(filePath)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}
