package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"github.com/xalgord/reconx/internal/logger"
	"os"
	"os/signal"
	"syscall"

	"github.com/xalgord/reconx/internal/config"
	"github.com/xalgord/reconx/internal/dashboard"
	"github.com/xalgord/reconx/internal/findings"
	"github.com/xalgord/reconx/internal/notify"
	"github.com/xalgord/reconx/internal/pipeline"
	"github.com/xalgord/reconx/internal/state"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "init":
		cmdInit()
	case "check":
		cmdCheck(os.Args[2:])
	case "version":
		fmt.Printf("reconx v%s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`ReconX — 24x7 Security Reconnaissance & Vulnerability Scanner

Usage:
  reconx <command> [flags]

Commands:
  run       Start the 24x7 recon + scan pipeline
  init      Generate example config at ~/.config/reconx/config.yaml
  check     Validate config and check tool availability
  version   Print version information
  help      Show this help message

Flags (for 'run' and 'check'):
  -config   Path to config file (default: ~/.config/reconx/config.yaml)

Examples:
  reconx init                          # Generate example config
  reconx check                         # Validate config + tools
  reconx run                           # Start with default config
  reconx run -config /path/to/config   # Start with custom config`)
}

func cmdInit() {
	cfgDir := config.DefaultConfigDir()
	cfgPath := config.DefaultConfigPath()

	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating config dir: %v\n", err)
		os.Exit(1)
	}

	// Don't overwrite existing config
	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Printf("Config already exists at %s\n", cfgPath)
		fmt.Println("Remove it first if you want to regenerate.")
		return
	}

	if err := os.WriteFile(cfgPath, []byte(config.GenerateExampleConfig()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Config generated at: %s\n", cfgPath)
	fmt.Println("Edit the file to set your targets_file and Discord webhooks.")
}

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath(), "path to config file")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Config error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Config loaded from: %s\n", *cfgPath)
	fmt.Printf("   Targets file: %s\n", cfg.TargetsFile)
	fmt.Printf("   Data dir: %s\n", cfg.DataDir)
	fmt.Printf("   Dashboard: %s:%d (enabled=%t)\n", cfg.Dashboard.Host, cfg.Dashboard.Port, cfg.Dashboard.Enabled)
	fmt.Printf("   Discord: enabled=%t\n", cfg.Discord.Enabled)
	fmt.Println()

	fmt.Println("Tool Status:")
	missing := cfg.CheckTools()

	if len(missing) > 0 {
		fmt.Printf("\n❌ %d required tools missing: %v\n", len(missing), missing)
		os.Exit(1)
	}

	fmt.Println("\n✅ All required tools found. Ready to run.")
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath(), "path to config file")
	fs.Parse(args)

	// Load config
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	// Setup logging
	setupLogging(cfg)

	// Ensure directories
	if err := cfg.EnsureDirs(); err != nil {
		logger.Error("failed to create directories", "error", err)
		os.Exit(1)
	}

	logger.Info("reconx starting",
		"version", version,
		"config", *cfgPath,
		"targets_file", cfg.TargetsFile,
	)

	// Initialize components
	stateMgr := state.NewManager(cfg.StateFile())
	store := findings.NewStore(cfg.FindingsFile())
	notifier := notify.New(cfg.Discord)

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("shutdown signal received", "signal", sig)
		notifier.SendStatus("🛑 ReconX Stopped", fmt.Sprintf("Received %s signal", sig), nil)
		cancel()
	}()

	// Start dashboard in background if enabled
	if cfg.Dashboard.Enabled {
		dash := dashboard.New(&cfg.Dashboard, stateMgr, store, cfg.Logging.File)
		go func() {
			if err := dash.ListenAndServe(); err != nil {
				logger.Error("dashboard error", "error", err)
			}
		}()
	}

	// Run pipeline
	p := pipeline.New(cfg, stateMgr, store, notifier)

	if err := p.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("pipeline error", "error", err)
		os.Exit(1)
	}

	// Graceful shutdown
	stateMgr.Stop()
	logger.Info("reconx stopped")
}

func setupLogging(cfg *config.Config) {
	logger.SetLevel(cfg.Logging.Level)

	// Create log file writer
	var writers []io.Writer
	writers = append(writers, os.Stdout)

	if cfg.Logging.File != "" {
		os.MkdirAll(cfg.LogsDir, 0o755)
		logFile, err := os.OpenFile(cfg.Logging.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			writers = append(writers, logFile)
		}
	}

	logger.SetOutput(io.MultiWriter(writers...))
}

