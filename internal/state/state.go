package state

import (
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"
)

// State holds the current workflow state.
type State struct {
	Cycle              int    `json:"cycle"`
	Phase              string `json:"phase"`
	CurrentTarget      string `json:"current_target"`
	CurrentTargetIndex int    `json:"current_target_index"`
	ReconCompleted     int    `json:"recon_completed"`
	ScanCompleted      int    `json:"scan_completed"`
	TotalTargets       int    `json:"total_targets"`
	StartedAt          string `json:"started_at"`
	LastUpdate         string `json:"last_update"`
	FindingsCount      int    `json:"findings_count"`
	SubdomainsFound    int    `json:"subdomains_found"`
	LiveHostsFound     int    `json:"live_hosts_found"`
	StatusMessage      string `json:"status_message"`
}

// Stats tracks per-cycle statistics.
type Stats struct {
	ReconDone      int `json:"recon_done"`
	ScanDone       int `json:"scan_done"`
	NucleiFindings int `json:"nuclei_findings"`
	DASTFindings   int `json:"dast_findings"`
	URLsGathered   int `json:"urls_gathered"`
	TotalSubs      int `json:"total_subs"`
	TotalLive      int `json:"total_live"`
}

// Manager handles thread-safe state and stats management with periodic persistence.
type Manager struct {
	mu       sync.RWMutex
	state    State
	stats    Stats
	filePath string
	dirty    bool
	stopCh   chan struct{}
}

// NewManager creates a new state manager.
func NewManager(filePath string) *Manager {
	m := &Manager{
		filePath: filePath,
		stopCh:   make(chan struct{}),
	}
	m.load()
	go m.persistLoop()
	return m
}

// GetState returns a copy of the current state.
func (m *Manager) GetState() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// GetStats returns a copy of the current stats.
func (m *Manager) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// UpdateState applies updates to the state.
func (m *Manager) UpdateState(fn func(s *State)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(&m.state)
	m.state.LastUpdate = time.Now().Format(time.RFC3339)
	m.dirty = true
}

// UpdateStats adds to the stats counters.
func (m *Manager) UpdateStats(fn func(s *Stats)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(&m.stats)
}

// ResetStats zeros all stats counters.
func (m *Manager) ResetStats() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats = Stats{}
}

// AddReconDone increments recon completed counter.
func (m *Manager) AddReconDone(subs, live int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.ReconDone++
	m.stats.TotalSubs += subs
	m.stats.TotalLive += live
	m.state.ReconCompleted = m.stats.ReconDone
	m.state.SubdomainsFound = m.stats.TotalSubs
	m.state.LiveHostsFound = m.stats.TotalLive
	m.dirty = true
}

// AddScanDone increments scan completed counter with finding counts.
func (m *Manager) AddScanDone(nucleiFindings, dastFindings, urls int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.ScanDone++
	m.stats.NucleiFindings += nucleiFindings
	m.stats.DASTFindings += dastFindings
	m.stats.URLsGathered += urls
	m.state.ScanCompleted = m.stats.ScanDone
	m.state.FindingsCount = m.stats.NucleiFindings + m.stats.DASTFindings
	m.dirty = true
}

// SetStatusMessage updates the status message.
func (m *Manager) SetStatusMessage(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.StatusMessage = msg
	m.dirty = true
}

// SetCurrentTarget updates the current target being processed.
func (m *Manager) SetCurrentTarget(target string, index int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.CurrentTarget = target
	m.state.CurrentTargetIndex = index
	m.dirty = true
}

// Stop halts the persistence loop and saves final state.
func (m *Manager) Stop() {
	close(m.stopCh)
	m.persist()
}

func (m *Manager) load() {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		slog.Info("no previous state found, starting fresh")
		return
	}

	if err := json.Unmarshal(data, &m.state); err != nil {
		slog.Warn("failed to parse previous state", "error", err)
	}
}

func (m *Manager) persistLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.persist()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Manager) persist() {
	m.mu.RLock()
	if !m.dirty {
		m.mu.RUnlock()
		return
	}
	data, err := json.MarshalIndent(m.state, "", "  ")
	m.mu.RUnlock()

	if err != nil {
		slog.Error("failed to marshal state", "error", err)
		return
	}

	if err := os.WriteFile(m.filePath, data, 0o644); err != nil {
		slog.Error("failed to save state", "error", err)
		return
	}

	m.mu.Lock()
	m.dirty = false
	m.mu.Unlock()
}
