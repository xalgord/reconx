package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"github.com/xalgord/reconx/internal/logger"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/reconx/internal/config"
	"github.com/xalgord/reconx/internal/dast"
	"github.com/xalgord/reconx/internal/findings"
	"github.com/xalgord/reconx/internal/notify"
	"github.com/xalgord/reconx/internal/recon"
	"github.com/xalgord/reconx/internal/scanner"
	"github.com/xalgord/reconx/internal/state"
)

// Pipeline orchestrates the 24x7 recon + scan workflow.
type Pipeline struct {
	cfg      *config.Config
	state    *state.Manager
	store    *findings.Store
	notifier *notify.Notifier
}

// New creates a new pipeline.
func New(cfg *config.Config, st *state.Manager, store *findings.Store, notifier *notify.Notifier) *Pipeline {
	return &Pipeline{
		cfg:      cfg,
		state:    st,
		store:    store,
		notifier: notifier,
	}
}

// Run starts the infinite pipeline loop. Blocks until ctx is cancelled.
func (p *Pipeline) Run(ctx context.Context) error {
	st := p.state.GetState()
	cycle := st.Cycle

	logger.Info("starting pipeline",
		"starting_cycle", cycle+1,
	)

	for {
		select {
		case <-ctx.Done():
			logger.Info("pipeline stopped")
			return ctx.Err()
		default:
		}

		cycle++
		p.runCycle(ctx, cycle)

		if ctx.Err() != nil {
			break
		}

		delay := time.Duration(p.cfg.Pipeline.CycleDelay) * time.Second
		logger.Info("cycle complete, waiting before next",
			"cycle", cycle,
			"delay", delay,
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}

	return nil
}

func (p *Pipeline) runCycle(ctx context.Context, cycle int) {
	// Load and shuffle targets
	targets := loadTargets(p.cfg.TargetsFile)
	if len(targets) == 0 {
		logger.Error("no targets loaded")
		return
	}

	// Shuffle for each cycle
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})

	// Reset state for new cycle
	p.state.ResetStats()
	p.state.UpdateState(func(s *state.State) {
		s.Cycle = cycle
		s.Phase = "parallel_pipeline"
		s.TotalTargets = len(targets)
		s.StartedAt = time.Now().Format(time.RFC3339)
		s.ReconCompleted = 0
		s.ScanCompleted = 0
		s.SubdomainsFound = 0
		s.LiveHostsFound = 0
		s.FindingsCount = 0
		s.StatusMessage = fmt.Sprintf("Starting cycle %d (parallel pipeline)", cycle)
	})

	logger.Info("cycle started",
		"cycle", cycle,
		"targets", len(targets),
	)

	// Send cycle start notification
	p.notifier.SendCycleStart(cycle, len(targets))

	// Producer-consumer pipeline
	reconCh := make(chan *recon.Result, p.cfg.Pipeline.ParallelScans)
	var reconWG sync.WaitGroup
	var scanWG sync.WaitGroup

	// Start scan workers (consumers)
	for i := 0; i < p.cfg.Pipeline.ParallelScans; i++ {
		scanWG.Add(1)
		go func(workerID int) {
			defer scanWG.Done()
			p.scanWorker(ctx, workerID, reconCh, len(targets), cycle)
		}(i)
	}

	// Start recon workers (producers)
	reconWorkerCount := p.cfg.Recon.ParallelTargets
	batches := distributeBatches(targets, reconWorkerCount)

	for i, batch := range batches {
		if len(batch) == 0 {
			continue
		}
		reconWG.Add(1)
		go func(workerID int, targets []indexedTarget) {
			defer reconWG.Done()
			p.reconWorker(ctx, workerID, targets, reconCh, len(targets), cycle)
		}(i, batch)
	}

	// Wait for all recon workers to finish, then close the channel
	reconWG.Wait()
	close(reconCh)
	logger.Info("all recon workers finished", "cycle", cycle)

	// Wait for all scan workers to drain the channel
	scanWG.Wait()
	logger.Info("all scan workers finished", "cycle", cycle)

	// Get final stats
	stats := p.state.GetStats()
	totalFindings := stats.NucleiFindings + stats.DASTFindings

	// Send cycle complete notification
	p.notifier.SendCycleComplete(cycle, map[string]int{
		"Targets":      len(targets),
		"Subdomains":   stats.TotalSubs,
		"Live Hosts":   stats.TotalLive,
		"URLs":         stats.URLsGathered,
		"Nuclei CVE":   stats.NucleiFindings,
		"DAST":         stats.DASTFindings,
		"Total":        totalFindings,
	})

	// Update state
	p.state.UpdateState(func(s *state.State) {
		s.Phase = "completed"
		s.StatusMessage = fmt.Sprintf("Cycle %d complete. Findings: %d", cycle, totalFindings)
	})

	// Cleanup output files
	p.cleanupCycle()
}

func (p *Pipeline) reconWorker(ctx context.Context, workerID int, targets []indexedTarget, out chan<- *recon.Result, total, cycle int) {
	for _, t := range targets {
		if ctx.Err() != nil {
			return
		}

		p.state.SetCurrentTarget(t.Target, t.Index)

		result, err := recon.RunRecon(ctx, p.cfg, t.Target, t.Index, total)
		if err != nil {
			logger.Error("recon error", "target", t.Target, "error", err)
			continue
		}

		// Update stats
		p.state.AddReconDone(result.SubdomainCount, result.LiveHostCount)

		stats := p.state.GetStats()
		p.state.SetStatusMessage(fmt.Sprintf(
			"Recon: %d/%d | Scan: %d/%d",
			stats.ReconDone, total, stats.ScanDone, total,
		))

		if result.LiveHostCount > 0 {
			out <- result
		} else {
			// Count as scanned (skipped — no live hosts)
			p.state.AddScanDone(0, 0, 0)
		}
	}
}

func (p *Pipeline) scanWorker(ctx context.Context, workerID int, in <-chan *recon.Result, totalTargets, cycle int) {
	for result := range in {
		if ctx.Err() != nil {
			return
		}

		target := result.Target
		p.state.SetCurrentTarget(target, result.TargetIndex)

		logger.Info("starting full scan",
			"target", target,
			"live_hosts", result.LiveHostCount,
			"worker", workerID,
		)

		// Run Nuclei CVE scan
		nucleiFindings := scanner.RunNucleiCVE(ctx, p.cfg, result, p.store, cycle)

		// Run DAST
		dastResult := dast.RunDAST(ctx, p.cfg, result, p.store, cycle)

		// Update stats
		dastFindings := 0
		urlsGathered := 0
		if dastResult != nil {
			dastFindings = dastResult.DASTFindings
			urlsGathered = dastResult.URLsGathered
		}
		p.state.AddScanDone(len(nucleiFindings), dastFindings, urlsGathered)

		stats := p.state.GetStats()
		totalFindings := stats.NucleiFindings + stats.DASTFindings
		p.state.SetStatusMessage(fmt.Sprintf(
			"Recon: %d/%d | Scan: %d/%d | Findings: %d",
			stats.ReconDone, totalTargets, stats.ScanDone, totalTargets, totalFindings,
		))

		// Send notifications for new findings
		p.notifyFindings(target, nucleiFindings, "Nuclei CVE")
	}
}

func (p *Pipeline) notifyFindings(target string, newFindings []findings.Finding, scanType string) {
	if len(newFindings) == 0 {
		return
	}

	// Group by domain
	byDomain := make(map[string][]findings.Finding)
	for _, f := range newFindings {
		domain := extractHostFromURL(f.MatchedAt)
		if domain == "" {
			domain = target
		}
		byDomain[domain] = append(byDomain[domain], f)
	}

	for domain, domainFindings := range byDomain {
		// Send individual critical findings
		for _, f := range domainFindings {
			p.notifier.SendCriticalFinding(domain, f.TemplateID, f.Name, f.Severity, f.MatchedAt)
		}

		// Send batch summary
		summaryItems := make([]map[string]string, len(domainFindings))
		for i, f := range domainFindings {
			summaryItems[i] = map[string]string{
				"template_id": f.TemplateID,
				"matched_at":  f.MatchedAt,
			}
		}
		p.notifier.SendFindingsSummary(domain, scanType, summaryItems)
	}
}

func (p *Pipeline) cleanupCycle() {
	entries, err := os.ReadDir(p.cfg.OutputDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		fullPath := p.cfg.OutputDir + "/" + entry.Name()
		if entry.IsDir() {
			os.RemoveAll(fullPath)
		}
	}

	logger.Info("cleaned up cycle output")
}

// --- Helpers ---

type indexedTarget struct {
	Target string
	Index  int
}

func distributeBatches(targets []string, numWorkers int) [][]indexedTarget {
	batches := make([][]indexedTarget, numWorkers)
	for i, t := range targets {
		batchIdx := i % numWorkers
		batches[batchIdx] = append(batches[batchIdx], indexedTarget{
			Target: t,
			Index:  i,
		})
	}
	return batches
}

func loadTargets(filePath string) []string {
	f, err := os.Open(filePath)
	if err != nil {
		logger.Error("failed to load targets", "file", filePath, "error", err)
		return nil
	}
	defer f.Close()

	var targets []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	logger.Info("loaded targets", "count", len(targets), "file", filePath)
	return targets
}

func extractHostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
