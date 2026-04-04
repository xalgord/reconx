package dast

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/reconx/internal/config"
	"github.com/xalgord/reconx/internal/findings"
	"github.com/xalgord/reconx/internal/logger"
	"github.com/xalgord/reconx/internal/recon"
	"github.com/xalgord/reconx/internal/runner"
	"github.com/xalgord/reconx/internal/scanner"
)

// Result holds the outcome of the DAST phase.
type Result struct {
	Target       string
	URLsGathered int
	DASTFindings int
}

// RunDAST performs the full DAST phase for a target:
// 1. Gather URLs (waymore + paramspider)
// 2. Deduplicate with uro
// 3. Run nuclei -dast
func RunDAST(ctx context.Context, cfg *config.Config, reconResult *recon.Result, store *findings.Store, cycle int) *Result {
	target := reconResult.Target
	outputDir := reconResult.OutputDir

	logger.Info("starting DAST phase", "target", target)

	// Step 1: Gather URLs
	urlsFile := gatherURLs(ctx, cfg, target, reconResult.LiveSubsFile, outputDir)

	urlCount := recon.CountLines(urlsFile)
	if urlCount == 0 {
		logger.Info("no URLs found for DAST", "target", target)
		return &Result{Target: target}
	}

	logger.Info("DAST URLs ready", "target", target, "urls", urlCount)

	// Step 2: Run nuclei DAST
	dastFindings := runNucleiDAST(ctx, cfg, urlsFile, outputDir, target, store, cycle)

	logger.Info("DAST phase complete",
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
		logger.Warn("no live subdomains for URL gathering", "target", target)
		return filepath.Join(outputDir, "all_urls.txt")
	}

	// Use the target itself as the root domain for waymore/gospider
	// (extracting from subdomains fails on multi-part TLDs like .gov.pk, .co.uk)
	rootDomains := map[string]bool{target: true}

	logger.Info("gathering URLs",
		"target", target,
		"subdomains", len(subdomains),
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
				logger.Info("waymore done", "domain", d, "urls_found", len(urls))
			}(domain)
		}
	} else {
		logger.Warn("waymore not found, skipping archive URL gathering")
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

	// Run gospider on live subdomains (if available)
	if cfg.Tools.Gospider != "" {
		for domain := range rootDomains {
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				urls := runGospider(ctx, cfg, d, subdomains, urlsDir)
				mu.Lock()
				for _, u := range urls {
					allURLs[u] = true
				}
				mu.Unlock()
				logger.Info("gospider done", "domain", d, "urls_found", len(urls))
			}(domain)
		}
	}

	wg.Wait()

	// Collect ALL URLs (no aggressive param-only filter)
	// nuclei -dast can test any URL, not just parameterized ones
	var cleanURLs []string
	for url := range allURLs {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}
		// Basic sanity: must look like a URL
		if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
			cleanURLs = append(cleanURLs, url)
		}
	}

	// Write raw URLs
	rawFile := filepath.Join(outputDir, "all_urls_raw.txt")
	writeLines(rawFile, cleanURLs)

	logger.Info("gathered raw URLs", "target", target, "count", len(cleanURLs))

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

	logger.Info("running waymore", "domain", domain)
	timeout := time.Duration(cfg.DAST.WaymoreTimeout) * time.Second
	result := runner.Run(ctx, cmd, timeout)

	if !result.Success {
		logger.Warn("waymore completed with errors",
			"domain", domain,
			"error", result.Err,
			"stderr", truncateStr(result.Stderr, 500),
		)
	}

	// Read from the -oU output file
	urls := readLines(outputFile)

	// Fallback: check waymore's default output directory
	if len(urls) == 0 {
		homeDir, _ := os.UserHomeDir()
		defaultDir := filepath.Join(homeDir, ".waymore", "results", domain)
		defaultFile := filepath.Join(defaultDir, "waymore.txt")
		if _, err := os.Stat(defaultFile); err == nil {
			logger.Info("reading waymore default output", "path", defaultFile)
			urls = readLines(defaultFile)
		}

		// Also try URLs file in default dir
		urlsDefault := filepath.Join(defaultDir, "URLs.txt")
		if _, err := os.Stat(urlsDefault); err == nil {
			logger.Info("reading waymore URLs.txt", "path", urlsDefault)
			extra := readLines(urlsDefault)
			urls = append(urls, extra...)
		}
	}

	return urls
}

func runParamspider(ctx context.Context, cfg *config.Config, subdomain, urlsDir string) []string {
	// ParamSpider saves to results/<subdomain>.txt or output/<subdomain>.txt relative to cwd
	os.MkdirAll(filepath.Join(urlsDir, "results"), 0o755)
	os.MkdirAll(filepath.Join(urlsDir, "output"), 0o755)

	cmd := []string{
		cfg.Tools.Paramspider,
		"-d", subdomain,
	}

	logger.Info("running paramspider", "subdomain", subdomain)
	timeout := time.Duration(cfg.DAST.ParamspiderTimeout) * time.Second
	result := runner.RunWithWorkDir(ctx, cmd, urlsDir, timeout)
	if !result.Success {
		logger.Warn("paramspider error",
			"subdomain", subdomain,
			"error", result.Err,
			"stderr", truncateStr(result.Stderr, 300),
		)
	}

	// Check multiple possible output locations
	var allURLs []string
	candidates := []string{
		filepath.Join(urlsDir, "results", subdomain+".txt"),
		filepath.Join(urlsDir, "output", subdomain+".txt"),
		filepath.Join(urlsDir, subdomain+".txt"),
	}

	for _, path := range candidates {
		if lines := readLines(path); len(lines) > 0 {
			logger.Info("paramspider output found", "path", path, "urls", len(lines))
			allURLs = append(allURLs, lines...)
		}
	}

	return allURLs
}

func runGospider(ctx context.Context, cfg *config.Config, domain string, subdomains []string, urlsDir string) []string {
	gospiderDir := filepath.Join(urlsDir, fmt.Sprintf("gospider_%s", strings.ReplaceAll(domain, ".", "_")))
	os.MkdirAll(gospiderDir, 0o755)

	// Build list of seed sites from live subdomains
	// gospider -S <file> reads sites from a file
	seedFile := filepath.Join(urlsDir, fmt.Sprintf("gospider_seeds_%s.txt", strings.ReplaceAll(domain, ".", "_")))
	var seeds []string
	for _, sub := range subdomains {
		sub = strings.TrimSpace(sub)
		if sub != "" {
			if !strings.HasPrefix(sub, "http") {
				seeds = append(seeds, "http://"+sub)
			} else {
				seeds = append(seeds, sub)
			}
		}
	}

	// If no subdomains, use root domain
	if len(seeds) == 0 {
		seeds = append(seeds, "http://"+domain)
	}

	// Limit seeds to avoid overwhelming a small server
	maxSeeds := 20
	if len(seeds) > maxSeeds {
		seeds = seeds[:maxSeeds]
	}

	writeLines(seedFile, seeds)

	cmd := []string{
		cfg.Tools.Gospider,
		"-S", seedFile,
		"-o", gospiderDir,
		"-c", fmt.Sprintf("%d", cfg.DAST.GospiderConcurrency),
		"-d", fmt.Sprintf("%d", cfg.DAST.GospiderDepth),
		"--other-source",
		"--include-subs",
		"-q", // quiet mode — only output URLs
	}

	logger.Info("running gospider", "domain", domain, "seeds", len(seeds))
	timeout := time.Duration(cfg.DAST.GospiderTimeout) * time.Second
	result := runner.Run(ctx, cmd, timeout)

	if !result.Success {
		logger.Warn("gospider completed with errors",
			"domain", domain,
			"error", result.Err,
			"stderr", truncateStr(result.Stderr, 500),
		)
	}

	// Parse gospider output files — each line may have tags like:
	// [url] - [code-200] - https://example.com/page
	// [href] - https://example.com/page
	// [form] - https://example.com/submit
	// Or in quiet mode, just raw URLs
	var allURLs []string

	entries, err := os.ReadDir(gospiderDir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		lines := readLines(filepath.Join(gospiderDir, entry.Name()))
		for _, line := range lines {
			url := extractGospiderURL(line)
			if url != "" {
				allURLs = append(allURLs, url)
			}
		}
	}

	// Clean up seed file
	os.Remove(seedFile)

	return allURLs
}

// extractGospiderURL pulls the actual URL from a gospider output line.
// Handles formats:
//
//	[url] - [code-200] - https://example.com/page
//	[href] - https://example.com/api
//	https://example.com/page  (quiet mode, no tags)
func extractGospiderURL(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Quiet mode: line is just a URL
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		return line
	}

	// Tagged format: find last "- http" segment
	if idx := strings.LastIndex(line, "- http"); idx != -1 {
		url := strings.TrimSpace(line[idx+2:])
		if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
			return url
		}
	}

	return ""
}

func runUro(ctx context.Context, cfg *config.Config, rawFile, outputDir string) string {
	outputFile := filepath.Join(outputDir, "all_urls.txt")

	if cfg.Tools.Uro == "" {
		// No uro available — use raw file as-is
		logger.Warn("uro not found, using raw URLs")
		copyFile(rawFile, outputFile)
		return outputFile
	}

	// Normalize URLs first (remove default ports)
	normalizedFile := filepath.Join(outputDir, "urls_normalized.txt")
	normalizeURLs(rawFile, normalizedFile)

	cmd := []string{cfg.Tools.Uro}

	logger.Info("running uro deduplication")
	timeout := time.Duration(cfg.DAST.UroTimeout) * time.Second
	result := runner.RunWithStdin(ctx, cmd, normalizedFile, outputFile, timeout)

	// Clean up temp file
	os.Remove(normalizedFile)

	if !result.Success {
		logger.Warn("uro error, using raw URLs", "error", result.Err)
		copyFile(rawFile, outputFile)
	} else {
		rawCount := recon.CountLines(rawFile)
		uroCount := recon.CountLines(outputFile)
		logger.Info("uro deduplication complete",
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
	for _, tag := range cfg.Nuclei.ExcludeTags {
		cmd = append(cmd, "-exclude-tags", tag)
	}
	for _, tag := range cfg.Nuclei.IncludeTags {
		cmd = append(cmd, "-tags", tag)
	}
	for _, tmpl := range cfg.Nuclei.ExcludeTemplates {
		cmd = append(cmd, "-exclude-templates", tmpl)
	}
	for _, tmpl := range cfg.Nuclei.IncludeTemplates {
		cmd = append(cmd, "-templates", tmpl)
	}

	logger.Info("running nuclei DAST", "target", target, "urls", urlCount)

	timeout := time.Duration(cfg.DAST.ScanTimeout) * time.Second
	result := runner.Run(ctx, cmd, timeout)

	if !result.Success && result.Err != nil {
		logger.Error("nuclei DAST error", "target", target, "error", result.Err)
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
	// Handle very long lines (some URLs can be 64KB+)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
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

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
