package findings

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/xalgord/reconx/internal/logger"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Finding represents a single vulnerability finding.
type Finding struct {
	TemplateID   string            `json:"template-id"`
	Name         string            `json:"name,omitempty"`
	Severity     string            `json:"severity,omitempty"`
	Host         string            `json:"host,omitempty"`
	MatchedAt    string            `json:"matched-at,omitempty"`
	Description  string            `json:"description,omitempty"`
	Info         map[string]interface{} `json:"info,omitempty"`
	ScanType     string            `json:"scan_type"`
	TargetDomain string            `json:"target_domain"`
	DiscoveredAt string            `json:"discovered_at"`
	Cycle        int               `json:"cycle"`
	Reference    []string          `json:"reference,omitempty"`
}

// Store manages thread-safe findings storage with deduplication.
// Uses JSONL format for efficient append-only writes and streaming reads.
type Store struct {
	mu       sync.RWMutex
	filePath string
	index    map[string]bool // dedup index: "template-id|matched-at"
	cache    []Finding       // in-memory cache for dashboard queries
	loaded   bool
}

// NewStore creates a new findings store.
func NewStore(filePath string) *Store {
	s := &Store{
		filePath: filePath,
		index:    make(map[string]bool),
	}
	s.loadIndex()
	return s
}

// Add saves a finding if it's unique. Returns true if it was new.
func (s *Store) Add(f Finding) bool {
	key := uniqueKey(f)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.index[key] {
		return false // duplicate
	}

	if f.DiscoveredAt == "" {
		f.DiscoveredAt = time.Now().Format(time.RFC3339)
	}

	// Populate name/severity from info map if present
	if f.Info != nil {
		if f.Name == "" {
			if name, ok := f.Info["name"].(string); ok {
				f.Name = name
			}
		}
		if f.Severity == "" {
			if sev, ok := f.Info["severity"].(string); ok {
				f.Severity = sev
			}
		}
		if f.Description == "" {
			if desc, ok := f.Info["description"].(string); ok {
				f.Description = desc
			}
		}
		if refs, ok := f.Info["reference"].([]interface{}); ok && len(f.Reference) == 0 {
			for _, r := range refs {
				if rs, ok := r.(string); ok {
					f.Reference = append(f.Reference, rs)
				}
			}
		}
	}

	// Append to file
	if err := s.appendToFile(f); err != nil {
		logger.Error("failed to save finding", "error", err)
		return false
	}

	s.index[key] = true
	s.cache = append(s.cache, f)

	return true
}

// Count returns the total number of findings.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.index)
}

// CountByCycle returns the number of findings for a specific cycle.
func (s *Store) CountByCycle(cycle int) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.ensureLoaded()
	count := 0
	for _, f := range s.cache {
		if f.Cycle == cycle {
			count++
		}
	}
	return count
}

// Query returns filtered, paginated findings.
func (s *Store) Query(opts QueryOpts) QueryResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.ensureLoaded()

	var filtered []Finding
	for _, f := range s.cache {
		if !opts.ShowHistory && opts.Cycle > 0 && f.Cycle != opts.Cycle {
			continue
		}
		if opts.Severity != "" && opts.Severity != "all" && !strings.EqualFold(f.Severity, opts.Severity) {
			continue
		}
		if opts.ScanType != "" && opts.ScanType != "all" && f.ScanType != opts.ScanType {
			continue
		}
		if opts.Domain != "" && !strings.Contains(strings.ToLower(f.Host), strings.ToLower(opts.Domain)) &&
			!strings.Contains(strings.ToLower(f.MatchedAt), strings.ToLower(opts.Domain)) {
			continue
		}
		if opts.TemplateID != "" && f.TemplateID != opts.TemplateID {
			continue
		}
		filtered = append(filtered, f)
	}

	// Sort by discovered_at descending
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].DiscoveredAt > filtered[j].DiscoveredAt
	})

	total := len(filtered)

	// Paginate
	page := opts.Page
	if page < 1 {
		page = 1
	}
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 50
	}

	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	return QueryResult{
		Findings:   filtered[start:end],
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: (total + perPage - 1) / perPage,
	}
}

// GetStats returns severity counts and unique hosts for optional cycle filter.
func (s *Store) GetStats(cycle int, showHistory bool) StatsResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.ensureLoaded()

	result := StatsResult{
		SeverityCounts: map[string]int{
			"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
		},
		UniqueHosts: make(map[string]bool),
		UniqueCVEs:  make(map[string]bool),
	}

	for _, f := range s.cache {
		if !showHistory && cycle > 0 && f.Cycle != cycle {
			continue
		}
		sev := strings.ToLower(f.Severity)
		if _, ok := result.SeverityCounts[sev]; ok {
			result.SeverityCounts[sev]++
		}
		result.UniqueHosts[f.Host] = true
		result.UniqueCVEs[f.TemplateID] = true
		result.Total++
	}

	result.AllTimeTotal = len(s.cache)
	return result
}

// GetCategories returns vulnerability categories grouped by template-id.
func (s *Store) GetCategories(cycle int, showHistory bool) []Category {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.ensureLoaded()

	cats := make(map[string]*Category)
	for _, f := range s.cache {
		if !showHistory && cycle > 0 && f.Cycle != cycle {
			continue
		}

		cat, ok := cats[f.TemplateID]
		if !ok {
			cat = &Category{
				ID:       f.TemplateID,
				Name:     f.Name,
				Severity: f.Severity,
				ScanType: f.ScanType,
				URLs:     make(map[string]bool),
				Hosts:    make(map[string]bool),
			}
			cats[f.TemplateID] = cat
		}
		cat.TotalHits++
		cat.URLs[f.MatchedAt] = true
		cat.Hosts[f.Host] = true
	}

	var result []Category
	for _, cat := range cats {
		cat.UniqueURLs = len(cat.URLs)
		cat.AffectedHosts = len(cat.Hosts)

		// Sample URLs
		i := 0
		for url := range cat.URLs {
			if i >= 5 {
				break
			}
			cat.SampleURLs = append(cat.SampleURLs, url)
			i++
		}

		result = append(result, *cat)
	}

	// Sort by severity then count
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(result, func(i, j int) bool {
		si := sevOrder[strings.ToLower(result[i].Severity)]
		sj := sevOrder[strings.ToLower(result[j].Severity)]
		if si != sj {
			return si < sj
		}
		return result[i].TotalHits > result[j].TotalHits
	})

	return result
}

// DeleteByCycle removes all findings from a specific cycle.
func (s *Store) DeleteByCycle(cycle int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureLoaded()

	var kept []Finding
	deleted := 0
	for _, f := range s.cache {
		if f.Cycle == cycle {
			delete(s.index, uniqueKey(f))
			deleted++
		} else {
			kept = append(kept, f)
		}
	}

	s.cache = kept

	if err := s.rewriteFile(); err != nil {
		return 0, err
	}

	return deleted, nil
}

// DeleteAll removes all findings.
func (s *Store) DeleteAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache = nil
	s.index = make(map[string]bool)

	return os.WriteFile(s.filePath, nil, 0o644)
}

// QueryOpts defines filtering options for findings query.
type QueryOpts struct {
	Cycle       int
	Severity    string
	ScanType    string
	Domain      string
	TemplateID  string
	ShowHistory bool
	Page        int
	PerPage     int
}

// QueryResult holds paginated query results.
type QueryResult struct {
	Findings   []Finding `json:"findings"`
	Total      int       `json:"total"`
	Page       int       `json:"page"`
	PerPage    int       `json:"per_page"`
	TotalPages int       `json:"total_pages"`
}

// StatsResult holds aggregated statistics.
type StatsResult struct {
	Total          int            `json:"total_findings"`
	AllTimeTotal   int            `json:"all_time_findings"`
	SeverityCounts map[string]int `json:"severity_counts"`
	UniqueHosts    map[string]bool `json:"-"`
	UniqueCVEs     map[string]bool `json:"-"`
}

// Category groups findings by template-id.
type Category struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Severity      string   `json:"severity"`
	ScanType      string   `json:"scan_type"`
	TotalHits     int      `json:"total_hits"`
	UniqueURLs    int      `json:"unique_urls"`
	AffectedHosts int      `json:"affected_hosts"`
	SampleURLs    []string `json:"sample_urls"`

	// internal
	URLs  map[string]bool `json:"-"`
	Hosts map[string]bool `json:"-"`
}

func uniqueKey(f Finding) string {
	matched := f.MatchedAt
	if matched == "" {
		matched = f.Host
	}
	return fmt.Sprintf("%s|%s", f.TemplateID, matched)
}

func (s *Store) loadIndex() {
	f, err := os.Open(s.filePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line buffer

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var finding Finding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}

		key := uniqueKey(finding)
		s.index[key] = true
		s.cache = append(s.cache, finding)
	}

	s.loaded = true
	logger.Info("loaded findings", "count", len(s.cache))
}

func (s *Store) ensureLoaded() {
	if !s.loaded {
		s.loadIndex()
	}
}

func (s *Store) appendToFile(f Finding) error {
	file, err := os.OpenFile(s.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := json.Marshal(f)
	if err != nil {
		return err
	}

	_, err = file.Write(append(data, '\n'))
	return err
}

func (s *Store) rewriteFile() error {
	file, err := os.Create(s.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, f := range s.cache {
		data, err := json.Marshal(f)
		if err != nil {
			continue
		}
		writer.Write(data)
		writer.WriteByte('\n')
	}

	return writer.Flush()
}
