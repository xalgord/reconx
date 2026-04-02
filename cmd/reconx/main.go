package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/xalgord/reconx/internal/config"
	"github.com/xalgord/reconx/internal/dashboard"
	"github.com/xalgord/reconx/internal/findings"
	"github.com/xalgord/reconx/internal/logger"
	"github.com/xalgord/reconx/internal/notify"
	"github.com/xalgord/reconx/internal/pipeline"
	"github.com/xalgord/reconx/internal/state"
)

const version = "1.0.3"

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
	case "service":
		cmdService(os.Args[2:])
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
  run             Start the 24x7 recon + scan pipeline
  init            Generate example config at ~/.config/reconx/config.yaml
  check           Validate config and check tool availability
  service         Manage systemd service (install/uninstall/status/logs)
  version         Print version information
  help            Show this help message

Flags (for 'run' and 'check'):
  -config         Path to config file (default: ~/.config/reconx/config.yaml)

Service Commands:
  reconx service install    Install and start systemd service
  reconx service uninstall  Stop and remove systemd service
  reconx service stop       Stop the service
  reconx service restart    Restart the service
  reconx service status     Show service status
  reconx service logs       Tail service logs (journalctl)

Examples:
  reconx init                          # Generate example config
  reconx check                         # Validate config + tools
  reconx run                           # Start (foreground)
  reconx service install               # Install as background service
  reconx service logs                  # Tail logs`)
}

func cmdInit() {
	cfgDir := config.DefaultConfigDir()
	cfgPath := config.DefaultConfigPath()

	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating config dir: %v\n", err)
		os.Exit(1)
	}

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

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	setupLogging(cfg)

	if err := cfg.EnsureDirs(); err != nil {
		logger.Error("failed to create directories", "error", err)
		os.Exit(1)
	}

	logger.Info("reconx starting",
		"version", version,
		"config", *cfgPath,
		"targets_file", cfg.TargetsFile,
	)

	stateMgr := state.NewManager(cfg.StateFile())
	store := findings.NewStore(cfg.FindingsFile())
	notifier := notify.New(cfg.Discord)

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

	if cfg.Dashboard.Enabled {
		dash := dashboard.New(&cfg.Dashboard, stateMgr, store, cfg.Logging.File)
		go func() {
			if err := dash.ListenAndServe(); err != nil {
				logger.Error("dashboard error", "error", err)
			}
		}()
	}

	p := pipeline.New(cfg, stateMgr, store, notifier)

	if err := p.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("pipeline error", "error", err)
		os.Exit(1)
	}

	stateMgr.Stop()
	logger.Info("reconx stopped")
}

// --- Service Management ---

const serviceName = "reconx"
const serviceFilePath = "/etc/systemd/system/reconx.service"

func cmdService(args []string) {
	if len(args) == 0 {
		fmt.Println(`Usage: reconx service <action>

Actions:
  install      Install and start reconx as a systemd service
  uninstall    Stop and remove the systemd service
  stop         Stop the service
  restart      Restart the service
  status       Show service status
  logs         Tail service logs (journalctl)`)
		return
	}

	switch args[0] {
	case "install":
		serviceInstall(args[1:])
	case "uninstall":
		serviceUninstall()
	case "status":
		serviceStatus()
	case "stop":
		serviceStop()
	case "logs":
		serviceLogs()
	case "restart":
		serviceRestart()
	default:
		fmt.Fprintf(os.Stderr, "Unknown service action: %s\n", args[0])
		os.Exit(1)
	}
}

func serviceInstall(args []string) {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "❌ Must run as root: sudo reconx service install")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("service install", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath(), "path to config file")
	fs.Parse(args)

	// Find reconx binary
	reconxBin, err := os.Executable()
	if err != nil {
		reconxBin, err = exec.LookPath("reconx")
		if err != nil {
			fmt.Fprintln(os.Stderr, "❌ Cannot find reconx binary path")
			os.Exit(1)
		}
	}
	reconxBin, _ = filepath.Abs(reconxBin)

	absCfgPath, _ := filepath.Abs(*cfgPath)

	if _, err := os.Stat(absCfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Config not found: %s\nRun 'reconx init' first.\n", absCfgPath)
		os.Exit(1)
	}

	// Build PATH with common tool directories
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		home, _ := os.UserHomeDir()
		goPath = filepath.Join(home, "go")
	}
	pathDirs := []string{
		filepath.Dir(reconxBin),
		filepath.Join(goPath, "bin"),
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
		"/snap/bin",
	}
	pathEnv := strings.Join(pathDirs, ":")

	unit := fmt.Sprintf(`[Unit]
Description=ReconX — 24x7 Security Recon & Vuln Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run -config %s
Restart=on-failure
RestartSec=30
Environment="PATH=%s"
StandardOutput=journal
StandardError=journal
SyslogIdentifier=reconx
LimitNOFILE=65535
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
`, reconxBin, absCfgPath, pathEnv)

	if err := os.WriteFile(serviceFilePath, []byte(unit), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to write service file: %v\n", err)
		os.Exit(1)
	}

	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", serviceName},
		{"systemctl", "start", serviceName},
	}

	for _, cmd := range cmds {
		c := exec.Command(cmd[0], cmd[1:]...)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed: %s — %v\n", strings.Join(cmd, " "), err)
			os.Exit(1)
		}
	}

	fmt.Println("\n✅ ReconX service installed and started!")
	fmt.Printf("   Binary:  %s\n", reconxBin)
	fmt.Printf("   Config:  %s\n", absCfgPath)
	fmt.Printf("   Service: %s\n", serviceFilePath)
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("   reconx service status    — check status")
	fmt.Println("   reconx service logs      — tail logs")
	fmt.Println("   reconx service restart   — restart")
	fmt.Println("   reconx service uninstall — stop & remove")
}

func serviceUninstall() {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "❌ Must run as root: sudo reconx service uninstall")
		os.Exit(1)
	}

	cmds := [][]string{
		{"systemctl", "stop", serviceName},
		{"systemctl", "disable", serviceName},
	}
	for _, cmd := range cmds {
		c := exec.Command(cmd[0], cmd[1:]...)
		c.Run()
	}

	os.Remove(serviceFilePath)
	exec.Command("systemctl", "daemon-reload").Run()

	fmt.Println("✅ ReconX service uninstalled.")
}

func serviceStatus() {
	c := exec.Command("systemctl", "status", serviceName)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Run()
}

func serviceLogs() {
	c := exec.Command("journalctl", "-u", serviceName, "-f", "--no-pager", "-n", "100")
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Run()
}

func serviceStop() {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "❌ Must run as root: sudo reconx service stop")
		os.Exit(1)
	}

	c := exec.Command("systemctl", "stop", serviceName)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Stop failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ ReconX service stopped.")
}

func serviceRestart() {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "❌ Must run as root: sudo reconx service restart")
		os.Exit(1)
	}

	c := exec.Command("systemctl", "restart", serviceName)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Restart failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ ReconX service restarted.")
}

func setupLogging(cfg *config.Config) {
	logger.SetLevel(cfg.Logging.Level)

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
