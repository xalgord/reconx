# ReconX

24x7 automated security reconnaissance & vulnerability scanning — single Go binary.

## Features

- **Parallel pipeline** — Recon workers feed directly into scan workers (goroutines + channels)
- **Subdomain enumeration** — subfinder, findomain, assetfinder (concurrent)
- **DNS resolution** — dnsx with configurable rate limits
- **Nuclei CVE scanning** — Critical/High severity with JSONL output
- **DAST scanning** — URL gathering (waymore + paramspider) → dedup (uro) → nuclei -dast
- **Discord notifications** — Rich embeds, color-coded by severity, multiple webhook targets
- **Web dashboard** — Dark-themed monitoring UI with findings, stats, filters, pagination
- **YAML config** — Everything configurable via `~/.config/reconx/config.yaml`
- **Single binary** — All web assets embedded, no external dependencies
- **Enforced timeouts** — Every subprocess has a configurable timeout (no more stuck workers)
- **Graceful shutdown** — Context cancellation propagation on SIGINT/SIGTERM

## Quick Start

```bash
# Build
go build -o reconx ./cmd/reconx/

# Generate config
./reconx init

# Edit config — set targets_file, dashboard password, Discord webhooks
vim ~/.config/reconx/config.yaml

# Validate config + check tools
./reconx check

# Start the pipeline
./reconx run
```

## Config

Config lives at `~/.config/reconx/config.yaml`. See [config.example.yaml](config.example.yaml) for all options.

Key settings:

```yaml
targets_file: "/path/to/targets.txt"

discord:
  enabled: true
  webhooks:
    critical: "https://discord.com/api/webhooks/..."
    status: "https://discord.com/api/webhooks/..."

dashboard:
  enabled: true
  host: "127.0.0.1"
  port: 8080
  username: "admin"
  password: "changeme"
```

## Commands

| Command | Description |
|---------|-------------|
| `reconx run` | Start the 24x7 pipeline |
| `reconx init` | Generate example config |
| `reconx check` | Validate config + check tools |
| `reconx version` | Print version |

## Required Tools

Must be in `$PATH` or configured in `tools:` section:

| Tool | Required | Purpose |
|------|----------|---------|
| subfinder | ✅ | Subdomain enumeration |
| dnsx | ✅ | DNS resolution |
| nuclei | ✅ | CVE + DAST scanning |
| findomain | Optional | Subdomain enumeration |
| assetfinder | Optional | Subdomain enumeration |
| waymore | Optional | URL gathering (archives) |
| paramspider | Optional | URL parameter discovery |
| uro | Optional | URL deduplication |

## Architecture

```
Targets File → [Recon Workers (5x)] → [Scan Queue] → [Scan Workers (10x)]
                    ↓                                       ↓
              subfinder                              Nuclei CVE
              findomain                              DAST Phase:
              assetfinder                              waymore
              → merge/dedup                            paramspider
              → dnsx resolve                           → uro dedup
                                                       → nuclei -dast
                                                            ↓
                                                    Findings Store (JSONL)
                                                            ↓
                                                  Discord Webhooks + Dashboard
```

## Data Locations

| Path | Content |
|------|---------|
| `~/.config/reconx/config.yaml` | Configuration |
| `~/.local/share/reconx/data/` | State, output |
| `~/.local/share/reconx/findings/` | Findings (JSONL) |
| `~/.local/share/reconx/logs/` | Log files |

## License

MIT
