package dast

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xalgord1/reconx/internal/config"
	"github.com/xalgord1/reconx/internal/findings"
	"github.com/xalgord1/reconx/internal/recon"
	"github.com/xalgord1/reconx/internal/runner"
	"github.com/xalgord1/reconx/internal/scanner"
)

// Result holds the outcome of the DAST phase.
type Result struct {
	Target       string
	URLsGathered int
	DASTFindings int
}

// RunDAST performs the full DAST phase for a target:
// 1. Gather URLs with parameters (waymore + paramspider)
// 2. Deduplicate with uro
// 3. Run nuclei -dast
func RunDAST(ctx context.Context, cfg *config.Config, reconResult *recon.Result, store *findings.Store, cycle int) *Result {
	target := reconResult.Target
	outputDir := reconResult.OutputDir

	slog.Info("starting DAST phase", "target", target)

	// Step 1: Gather URLs
	urlsFile := gatherURLs(ctx, cfg, target, reconResult.LiveSubsFile, outputDir)

	urlCount := recon.CountLines(urlsFile)
	if urlCount == 0 {
		slog.Info("no parameterized URLs found", "target", target)
		return &Result{Target: target}
	}

	// Step 2: Run nuclei DAST
	dastFindings := runNucleiDAST(ctx, cfg, urlsFile, outputDir, target, store, cycle)

	slog.Info("DAST phase complete",
		"target", target,
		"urls", urlCount,
		"findings", len(dastFindings),
	)

	return &Result{
		Target:       target,
		URLsGathered: urlCount,
		DASTFindings: len(dastFindings),
	}
}

func gatherURLs(ctx context.Context, cfg *config.Config, target, liveSubsFile, outputDir string) string {
	urlsDir := filepath.Join(outputDir, "urls")

	// Clear stale results from previous runs
	os.RemoveAll(urlsDir)
	os.MkdirAll(urlsDir, 0o755)

	allURLs := make(map[string]bool)
	var mu sync.Mutex

	// Read live subdomains
	subdomains := readLines(liveSubsFile)
	if len(subdomains) == 0 {
		return filepath.Join(outputDir, "all_urls.txt")
	}

	// Extract unique root domains for waymore
	rootDomains := make(map[string]bool)
	for _, sub := range subdomains {
		rootDomains[extractRootDomain(sub)] = true
	}

	slog.Info("gathering URLs",
		"target", target,
		"subdomains", len(subdomains),
		"root_domains", len(rootDomains),
	)

	var wg sync.WaitGroup

	// Run waymore on root domains (if available)
	if cfg.Tools.Waymore != "" {
		for domain := range rootDomains {
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				urls := runWaymore(ctx, cfg, d, urlsDir)
				mu.Lock()
				for _, u := range urls {
					allURLs[u] = true
				}
				mu.Unlock()
			}(domain)
		}
	}

	// Run paramspider on subdomains (limited, if available)
	if cfg.Tools.Paramspider != "" {
		limited := subdomains
		if len(limited) > cfg.DAST.MaxParamspiderSubs {
			limited = limited[:cfg.DAST.MaxParamspiderSubs]
		}

		for _, sub := range limited {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				urls := runParamspider(ctx, cfg, s, urlsDir)
				mu.Lock()
				for _, u := range urls {
					allURLs[u] = true
				}
				mu.Unlock()
			}(sub)
		}
	}

	wg.Wait()

	// Filter to only parameterized URLs
	var paramURLs []string
	for url := range allURLs {
		if strings.Contains(url, "?") && strings.Contains(url, "=") {
			paramURLs = append(paramURLs, url)
		}
	}

	// Write raw URLs
	rawFile := filepath.Join(outputDir, "all_urls_raw.txt")
	writeLines(rawFile, paramURLs)

	slog.Info("gathered raw URLs", "target", target, "count", len(paramURLs))

	// Deduplicate with uro
	return runUro(ctx, cfg, rawFile, outputDir)
}

func runWaymore(ctx context.Context, cfg *config.Config, domain, urlsDir string) []string {
	outputFile := filepath.Join(urlsDir, fmt.Sprintf("waymore_%s.txt", strings.ReplaceAll(domain, ".", "_")))

	cmd := []string{
		cfg.Tools.Waymore,
		"-i", domain,
		"-mode", "U",
		"-oU", outputFile,
	}

	slog.Info("running waymore", "domain", domain)
	timeout := time.Duration(cfg.DAST.WaymoreTimeout) * time.Second
	result := runner.Run(ctx, cmd, timeout)
	if !result.Success {
		slog.Warn("waymore error", "domain", domain, "error", result.Err)
	}

	return readLines(outputFile)
}

func runParamspider(ctx context.Context, cfg *config.Config, subdomain, urlsDir string) []string {
	// ParamSpider saves to results/<subdomain>.txt relative to cwd
	resultsDir := filepath.Join(urlsDir, "results")
	os.MkdirAll(resultsDir, 0o755)

	cmd := []string{
		cfg.Tools.Paramspider,
		"-d", subdomain,
	}

	slog.Info("running paramspider", "subdomain", subdomain)
	timeout := time.Duration(cfg.DAST.ParamspiderTimeout) * time.Second
	result := runner.RunWithWorkDir(ctx, cmd, urlsDir, timeout)
	if !result.Success {
		slog.Warn("paramspider error", "subdomain", subdomain, "error", result.Err)
	}

	// Read from the expected output location
	resultFile := filepath.Join(resultsDir, subdomain+".txt")
	return readLines(resultFile)
}

func runUro(ctx context.Context, cfg *config.Config, rawFile, outputDir string) string {
	outputFile := filepath.Join(outputDir, "all_urls.txt")

	if cfg.Tools.Uro == "" {
		// No uro available — use raw file as-is
		slog.Warn("uro not found, using raw URLs")
		copyFile(rawFile, outputFile)
		return outputFile
	}

	// Normalize URLs first (remove default ports)
	normalizedFile := filepath.Join(outputDir, "urls_normalized.txt")
	normalizeURLs(rawFile, normalizedFile)

	cmd := []string{cfg.Tools.Uro}

	slog.Info("running uro deduplication")
	timeout := time.Duration(cfg.DAST.UroTimeout) * time.Second
	result := runner.RunWithStdin(ctx, cmd, normalizedFile, outputFile, timeout)

	// Clean up temp file
	os.Remove(normalizedFile)

	if !result.Success {
		slog.Warn("uro error, using normalized URLs", "error", result.Err)
		copyFile(rawFile, outputFile)
	} else {
		rawCount := recon.CountLines(rawFile)
		uroCount := recon.CountLines(outputFile)
		slog.Info("uro deduplication complete",
			"before", rawCount,
			"after", uroCount,
			"removed", rawCount-uroCount,
		)
	}

	return outputFile
}

func runNucleiDAST(ctx context.Context, cfg *config.Config, urlsFile, outputDir, target string, store *findings.Store, cycle int) []findings.Finding {
	if cfg.Tools.Nuclei == "" {
		return nil
	}

	urlCount := recon.CountLines(urlsFile)
	if urlCount == 0 {
		return nil
	}

	outputFile := filepath.Join(outputDir, fmt.Sprintf("dast_output_%s.json", time.Now().Format("20060102_150405")))

	cmd := []string{
		cfg.Tools.Nuclei,
		"-l", urlsFile,
		"-dast",
		"-severity", cfg.NucleiSeverityStr(),
		"-rate-limit", fmt.Sprintf("%d", cfg.DAST.RateLimit),
		"-c", fmt.Sprintf("%d", cfg.DAST.Concurrency),
		"-timeout", fmt.Sprintf("%d", cfg.DAST.Timeout),
		"-jsonl",
		"-o", outputFile,
	}

	for _, id := range cfg.Nuclei.ExcludeIDs {
		cmd = append(cmd, "-exclude-id", id)
	}

	slog.Info("running nuclei DAST", "target", target, "urls", urlCount)

	timeout := time.Duration(cfg.DAST.ScanTimeout) * time.Second
	result := runner.Run(ctx, cmd, timeout)

	if !result.Success && result.Err != nil {
		slog.Error("nuclei DAST error", "target", target, "error", result.Err)
	}

	// Use shared parsing from scanner package
	return scanner.ParseAndSaveFindings(outputFile, store, target, "dast", cycle)
}

// --- Utility functions ---

func extractRootDomain(subdomain string) string {
	parts := strings.Split(strings.TrimSpace(subdomain), ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return subdomain
}

func readLines(filePath string) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func writeLines(filePath string, lines []string) {
	f, err := os.Create(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range lines {
		w.WriteString(line + "\n")
	}
	w.Flush()
}

func normalizeURLs(inputFile, outputFile string) {
	lines := readLines(inputFile)

	f, err := os.Create(outputFile)
	if err != nil {
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range lines {
		// Remove default ports
		normalized := strings.Replace(line, ":80/", "/", 1)
		normalized = strings.Replace(normalized, ":443/", "/", 1)
		w.WriteString(normalized + "\n")
	}
	w.Flush()
}

func copyFile(src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		return
	}
	os.WriteFile(dst, data, 0o644)
}
