package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/xalgord/reconx/internal/logger"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/reconx/internal/config"
	"github.com/xalgord/reconx/internal/findings"
	"github.com/xalgord/reconx/internal/recon"
	"github.com/xalgord/reconx/internal/runner"
)

// RunNucleiCVE runs a nuclei CVE scan on live hosts for a target.
// Returns the list of new (unique) findings saved.
func RunNucleiCVE(ctx context.Context, cfg *config.Config, reconResult *recon.Result, store *findings.Store, cycle int) []findings.Finding {
	if cfg.Nuclei.Enabled != nil && !*cfg.Nuclei.Enabled {
		logger.Info("nuclei CVE scan disabled in config")
		return nil
	}
	if cfg.Tools.Nuclei == "" {
		logger.Error("nuclei not found, skipping CVE scan")
		return nil
	}

	liveFile := reconResult.LiveSubsFile
	if _, err := os.Stat(liveFile); err != nil {
		return nil
	}

	hostCount := recon.CountLines(liveFile)
	if hostCount == 0 {
		return nil
	}

	// Output file
	outputFile := filepath.Join(reconResult.OutputDir, fmt.Sprintf("nuclei_cve_%s.json", time.Now().Format("20060102_150405")))

	cmd := []string{
		cfg.Tools.Nuclei,
		"-l", liveFile,
		"-severity", cfg.NucleiSeverityStr(),
		"-rate-limit", fmt.Sprintf("%d", cfg.Nuclei.RateLimit),
		"-concurrency", fmt.Sprintf("%d", cfg.Nuclei.Concurrency),
		"-bulk-size", fmt.Sprintf("%d", cfg.Nuclei.BulkSize),
		"-timeout", fmt.Sprintf("%d", cfg.Nuclei.Timeout),
		"-jsonl",
		"-o", outputFile,
	}

	// Add exclusions and filters
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

	logger.Info("running nuclei CVE scan",
		"target", reconResult.Target,
		"hosts", hostCount,
	)

	timeout := time.Duration(cfg.Nuclei.ScanTimeout) * time.Second
	result := runner.Run(ctx, cmd, timeout)

	if !result.Success && result.Err != nil {
		logger.Error("nuclei CVE scan error",
			"target", reconResult.Target,
			"error", result.Err,
		)
	}

	// Parse findings from output
	return ParseAndSaveFindings(outputFile, store, reconResult.Target, "nuclei-cve", cycle)
}

// ParseAndSaveFindings reads a nuclei JSONL output file, deduplicates, and saves findings.
func ParseAndSaveFindings(outputFile string, store *findings.Store, target, scanType string, cycle int) []findings.Finding {
	f, err := os.Open(outputFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var saved []findings.Finding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 512*1024), 512*1024) // 512KB line buffer

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		finding := findings.Finding{
			TemplateID:   getStr(raw, "template-id"),
			Host:         getStr(raw, "host"),
			MatchedAt:    getStr(raw, "matched-at"),
			ScanType:     scanType,
			TargetDomain: target,
			Cycle:        cycle,
		}

		// Extract info fields
		if info, ok := raw["info"].(map[string]interface{}); ok {
			finding.Info = info
			finding.Name = getStr(info, "name")
			finding.Severity = getStr(info, "severity")
			finding.Description = getStr(info, "description")

			if refs, ok := info["reference"].([]interface{}); ok {
				for _, r := range refs {
					if s, ok := r.(string); ok {
						finding.Reference = append(finding.Reference, s)
					}
				}
			}
		}

		if store.Add(finding) {
			saved = append(saved, finding)
		}
	}

	logger.Info("nuclei findings parsed",
		"target", target,
		"scan_type", scanType,
		"total_saved", len(saved),
	)

	return saved
}

func getStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
