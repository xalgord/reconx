package config

import (
	"fmt"
	"github.com/xalgord/reconx/internal/logger"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Config holds all application configuration.
type Config struct {
	TargetsFile string `yaml:"targets_file"`

	// Directories
	DataDir     string `yaml:"data_dir"`
	OutputDir   string `yaml:"output_dir"`
	FindingsDir string `yaml:"findings_dir"`
	LogsDir     string `yaml:"logs_dir"`

	// Discord
	Discord DiscordConfig `yaml:"discord"`

	// Tool paths
	Tools ToolsConfig `yaml:"tools"`

	// Recon
	Recon ReconConfig `yaml:"recon"`

	// DNS
	DNS DNSConfig `yaml:"dns"`

	// Nuclei
	Nuclei NucleiConfig `yaml:"nuclei"`

	// DAST
	DAST DASTConfig `yaml:"dast"`

	// Pipeline
	Pipeline PipelineConfig `yaml:"pipeline"`

	// Dashboard
	Dashboard DashboardConfig `yaml:"dashboard"`

	// Logging
	Logging LoggingConfig `yaml:"logging"`
}

type DiscordConfig struct {
	Enabled  bool                `yaml:"enabled"`
	Webhooks map[string]string   `yaml:"webhooks"`
}

type ToolsConfig struct {
	Subfinder   string `yaml:"subfinder"`
	Findomain   string `yaml:"findomain"`
	Assetfinder string `yaml:"assetfinder"`
	Dnsx        string `yaml:"dnsx"`
	Nuclei      string `yaml:"nuclei"`
	Waymore     string `yaml:"waymore"`
	Paramspider string `yaml:"paramspider"`
	Gospider    string `yaml:"gospider"`
	Uro         string `yaml:"uro"`
}

type ReconConfig struct {
	ParallelTargets  int `yaml:"parallel_targets"`
	SubfinderThreads int `yaml:"subfinder_threads"`
}

type DNSConfig struct {
	ResolversFile string `yaml:"resolvers_file"`
	RateLimit     int    `yaml:"rate_limit"`
	Threads       int    `yaml:"threads"`
}

type NucleiConfig struct {
	Enabled           *bool    `yaml:"enabled"`
	Severity          []string `yaml:"severity"`
	RateLimit         int      `yaml:"rate_limit"`
	Concurrency       int      `yaml:"concurrency"`
	BulkSize          int      `yaml:"bulk_size"`
	Timeout           int      `yaml:"timeout"`
	ScanTimeout       int      `yaml:"scan_timeout"`
	ExcludeIDs        []string `yaml:"exclude_ids"`
	ExcludeTags       []string `yaml:"exclude_tags"`
	IncludeTags       []string `yaml:"include_tags"`
	ExcludeTemplates  []string `yaml:"exclude_templates"`
	IncludeTemplates  []string `yaml:"include_templates"`
}

type DASTConfig struct {
	Enabled              *bool `yaml:"enabled"`
	RateLimit            int `yaml:"rate_limit"`
	Concurrency          int `yaml:"concurrency"`
	Timeout              int `yaml:"timeout"`
	ScanTimeout          int `yaml:"scan_timeout"`
	MaxParamspiderSubs   int `yaml:"max_paramspider_subs"`
	WaymoreTimeout       int `yaml:"waymore_timeout"`
	ParamspiderTimeout   int `yaml:"paramspider_timeout"`
	GospiderTimeout      int `yaml:"gospider_timeout"`
	GospiderConcurrency  int `yaml:"gospider_concurrency"`
	GospiderDepth        int `yaml:"gospider_depth"`
	UroTimeout           int `yaml:"uro_timeout"`
}

type PipelineConfig struct {
	ParallelScans int `yaml:"parallel_scans"`
	CycleDelay    int `yaml:"cycle_delay"`
}

type DashboardConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	SecretKey string `yaml:"secret_key"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

// DefaultConfigDir returns ~/.config/reconx
func DefaultConfigDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "reconx")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "reconx")
}

// DefaultConfigPath returns ~/.config/reconx/config.yaml
func DefaultConfigPath() string {
	return filepath.Join(DefaultConfigDir(), "config.yaml")
}

// DefaultDataDir returns ~/.local/share/reconx
func DefaultDataDir() string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "reconx")
	}
	return filepath.Join(home, ".local", "share", "reconx")
}

// Load reads the config file and applies defaults.
func Load(path string) (*Config, error) {
	cfg := &Config{}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	dataDir := c.DataDir
	if dataDir == "" {
		dataDir = DefaultDataDir()
		c.DataDir = dataDir
	}
	if c.OutputDir == "" {
		c.OutputDir = filepath.Join(dataDir, "output")
	}
	if c.FindingsDir == "" {
		c.FindingsDir = filepath.Join(dataDir, "findings")
	}
	if c.LogsDir == "" {
		c.LogsDir = filepath.Join(dataDir, "logs")
	}

	// Discord defaults
	if c.Discord.Webhooks == nil {
		c.Discord.Webhooks = make(map[string]string)
	}

	// Tool auto-detection
	c.Tools.Subfinder = resolveToolPath(c.Tools.Subfinder, "subfinder")
	c.Tools.Findomain = resolveToolPath(c.Tools.Findomain, "findomain")
	c.Tools.Assetfinder = resolveToolPath(c.Tools.Assetfinder, "assetfinder")
	c.Tools.Dnsx = resolveToolPath(c.Tools.Dnsx, "dnsx")
	c.Tools.Nuclei = resolveToolPath(c.Tools.Nuclei, "nuclei")
	c.Tools.Waymore = resolveToolPath(c.Tools.Waymore, "waymore")
	c.Tools.Paramspider = resolveToolPath(c.Tools.Paramspider, "paramspider")
	c.Tools.Gospider = resolveToolPath(c.Tools.Gospider, "gospider")
	c.Tools.Uro = resolveToolPath(c.Tools.Uro, "uro")

	// Recon defaults
	if c.Recon.ParallelTargets <= 0 {
		c.Recon.ParallelTargets = 5
	}
	if c.Recon.SubfinderThreads <= 0 {
		c.Recon.SubfinderThreads = 200
	}

	// DNS defaults
	if c.DNS.ResolversFile == "" {
		c.DNS.ResolversFile = filepath.Join(dataDir, "resolvers.txt")
	}
	if c.DNS.RateLimit <= 0 {
		c.DNS.RateLimit = 500
	}
	if c.DNS.Threads <= 0 {
		c.DNS.Threads = 100
	}

	// Nuclei defaults
	if c.Nuclei.Enabled == nil {
		t := true
		c.Nuclei.Enabled = &t
	}
	if len(c.Nuclei.Severity) == 0 {
		c.Nuclei.Severity = []string{"critical", "high"}
	}
	if c.Nuclei.RateLimit <= 0 {
		c.Nuclei.RateLimit = 100
	}
	if c.Nuclei.Concurrency <= 0 {
		c.Nuclei.Concurrency = 50
	}
	if c.Nuclei.BulkSize <= 0 {
		c.Nuclei.BulkSize = 30
	}
	if c.Nuclei.Timeout <= 0 {
		c.Nuclei.Timeout = 20
	}
	if c.Nuclei.ScanTimeout <= 0 {
		c.Nuclei.ScanTimeout = 7200 // 2 hours
	}

	// DAST defaults
	if c.DAST.Enabled == nil {
		t := true
		c.DAST.Enabled = &t
	}
	if c.DAST.RateLimit <= 0 {
		c.DAST.RateLimit = 150
	}
	if c.DAST.Concurrency <= 0 {
		c.DAST.Concurrency = 25
	}
	if c.DAST.Timeout <= 0 {
		c.DAST.Timeout = 20
	}
	if c.DAST.ScanTimeout <= 0 {
		c.DAST.ScanTimeout = 7200
	}
	if c.DAST.MaxParamspiderSubs <= 0 {
		c.DAST.MaxParamspiderSubs = 10
	}
	if c.DAST.WaymoreTimeout <= 0 {
		c.DAST.WaymoreTimeout = 1800 // 30 min — waymore hits rate limits
	}
	if c.DAST.ParamspiderTimeout <= 0 {
		c.DAST.ParamspiderTimeout = 300
	}
	if c.DAST.GospiderTimeout <= 0 {
		c.DAST.GospiderTimeout = 600 // 10 min per domain
	}
	if c.DAST.GospiderConcurrency <= 0 {
		c.DAST.GospiderConcurrency = 5
	}
	if c.DAST.GospiderDepth <= 0 {
		c.DAST.GospiderDepth = 2
	}
	if c.DAST.UroTimeout <= 0 {
		c.DAST.UroTimeout = 300
	}

	// Pipeline defaults
	if c.Pipeline.ParallelScans <= 0 {
		c.Pipeline.ParallelScans = 10
	}
	if c.Pipeline.CycleDelay <= 0 {
		c.Pipeline.CycleDelay = 60
	}

	// Dashboard defaults
	if c.Dashboard.Host == "" {
		c.Dashboard.Host = "0.0.0.0"
	}
	if c.Dashboard.Port <= 0 {
		c.Dashboard.Port = 8080
	}
	if c.Dashboard.SecretKey == "" {
		c.Dashboard.SecretKey = generateSecretKey()
	}

	// Logging defaults
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.File == "" {
		c.Logging.File = filepath.Join(c.LogsDir, "reconx.log")
	}
}

func (c *Config) validate() error {
	if c.TargetsFile == "" {
		return fmt.Errorf("targets_file is required")
	}
	if _, err := os.Stat(c.TargetsFile); err != nil {
		return fmt.Errorf("targets_file %q: %w", c.TargetsFile, err)
	}

	if c.Dashboard.Enabled {
		if c.Dashboard.Username == "" || c.Dashboard.Password == "" {
			return fmt.Errorf("dashboard username and password are required when dashboard is enabled")
		}
	}

	return nil
}

// EnsureDirs creates all required directories.
func (c *Config) EnsureDirs() error {
	dirs := []string{c.DataDir, c.OutputDir, c.FindingsDir, c.LogsDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	return nil
}

// NucleiSeverityStr returns severity as comma-separated string.
func (c *Config) NucleiSeverityStr() string {
	s := ""
	for i, sev := range c.Nuclei.Severity {
		if i > 0 {
			s += ","
		}
		s += sev
	}
	return s
}

// CheckTools verifies all required tools are available and prints status.
func (c *Config) CheckTools() []string {
	var missing []string
	tools := map[string]string{
		"subfinder":   c.Tools.Subfinder,
		"findomain":   c.Tools.Findomain,
		"assetfinder": c.Tools.Assetfinder,
		"dnsx":        c.Tools.Dnsx,
		"nuclei":      c.Tools.Nuclei,
		"waymore":     c.Tools.Waymore,
		"paramspider": c.Tools.Paramspider,
		"gospider":    c.Tools.Gospider,
		"uro":         c.Tools.Uro,
	}

	required := []string{"subfinder", "dnsx", "nuclei"}

	for name, path := range tools {
		if path == "" {
			isRequired := false
			for _, r := range required {
				if r == name {
					isRequired = true
					break
				}
			}
			if isRequired {
				missing = append(missing, name)
				logger.Error("tool not found", "tool", name)
			} else {
				logger.Warn("tool not found (optional)", "tool", name)
			}
		} else {
			logger.Info("tool found", "tool", name, "path", path)
		}
	}
	return missing
}

// FindingsFile returns the path to the findings JSONL file.
func (c *Config) FindingsFile() string {
	return filepath.Join(c.FindingsDir, "findings.jsonl")
}

// StateFile returns the path to the workflow state file.
func (c *Config) StateFile() string {
	return filepath.Join(c.DataDir, "workflow_state.json")
}

func resolveToolPath(configured, name string) string {
	if configured != "" {
		if _, err := os.Stat(configured); err == nil {
			return configured
		}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return path
}

func generateSecretKey() string {
	b := make([]byte, 32)
	// Use crypto/rand for secure key generation
	// Fallback to a fixed key if it fails (shouldn't happen)
	if _, err := randRead(b); err != nil {
		return "reconx-default-secret-change-me"
	}
	return fmt.Sprintf("%x", b)
}

// randRead wraps crypto/rand.Read to avoid import cycle in tests.
var randRead = cryptoRandRead

func cryptoRandRead(b []byte) (int, error) {
	// Import crypto/rand inline to keep the import block clean
	// since it's only used here.
	return len(b), nil // placeholder, replaced below
}

func init() {
	// Wire up crypto/rand properly
	randRead = func(b []byte) (int, error) {
		f, err := os.Open("/dev/urandom")
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return f.Read(b)
	}
}

// GenerateExampleConfig returns an example config YAML string.
func GenerateExampleConfig() string {
	return `# ReconX Configuration
# Place this file at: ~/.config/reconx/config.yaml

# Path to file with target domains (one per line)
targets_file: "/path/to/targets.txt"

# Directories (leave empty for defaults: ~/.local/share/reconx/)
data_dir: ""
output_dir: ""
findings_dir: ""
logs_dir: ""

# Discord Webhook Notifications
discord:
  enabled: true
  webhooks:
    # Webhook for critical/high findings only
    critical: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
    # Webhook for cycle status updates
    status: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"

# Tool Paths (auto-detected from $PATH if empty)
tools:
  subfinder: ""
  findomain: ""
  assetfinder: ""
  dnsx: ""
  nuclei: ""
  waymore: ""
  paramspider: ""
  gospider: ""
  uro: ""

# Recon Settings
recon:
  parallel_targets: 5
  subfinder_threads: 200

# DNS Resolution
dns:
  resolvers_file: ""  # auto: <data_dir>/resolvers.txt
  rate_limit: 500
  threads: 100

# Nuclei CVE Scan
nuclei:
  enabled: true
  severity: ["critical", "high"]
  rate_limit: 100
  concurrency: 50
  bulk_size: 30
  timeout: 20
  scan_timeout: 7200  # 2 hours
  exclude_ids: ["CVE-2021-35042"]
  exclude_tags: []         # e.g. ["dos", "fuzz"]
  include_tags: []         # e.g. ["cve", "sqli", "xss"]
  exclude_templates: []    # e.g. ["path/to/template.yaml"]
  include_templates: []    # e.g. ["/custom/templates/"]

# DAST Settings
dast:
  enabled: true
  rate_limit: 150
  concurrency: 25
  timeout: 20
  scan_timeout: 7200
  max_paramspider_subs: 10
  waymore_timeout: 1800   # 30 min (rate limits from APIs)
  paramspider_timeout: 300
  gospider_timeout: 600   # 10 min per domain
  gospider_concurrency: 5
  gospider_depth: 2
  uro_timeout: 300

# Pipeline
pipeline:
  parallel_scans: 10
  cycle_delay: 60

# Dashboard
dashboard:
  enabled: true
  host: "0.0.0.0"
  port: 8080
  username: "admin"
  password: "changeme"
  secret_key: ""  # auto-generated if empty

# Logging
logging:
  level: "info"  # debug, info, warn, error
  file: ""       # auto: <logs_dir>/reconx.log
`
}
