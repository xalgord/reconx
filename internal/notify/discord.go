package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/xalgord/reconx/internal/config"
)

// Severity color codes for Discord embeds.
const (
	ColorCritical = 0xFF0000 // Red
	ColorHigh     = 0xFF6600 // Orange
	ColorMedium   = 0xFFCC00 // Yellow
	ColorLow      = 0x00CC00 // Green
	ColorInfo     = 0x0099FF // Blue
	ColorStatus   = 0x7289DA // Discord Blurple
)

// Discord webhook payload structures.
type discordPayload struct {
	Content string         `json:"content,omitempty"`
	Embeds  []discordEmbed `json:"embeds,omitempty"`
}

type discordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Fields      []discordEmbedField `json:"fields,omitempty"`
	Footer      *discordEmbedFooter `json:"footer,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
}

type discordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type discordEmbedFooter struct {
	Text string `json:"text"`
}

// Notifier sends notifications via Discord webhooks.
type Notifier struct {
	cfg    config.DiscordConfig
	client *http.Client
	queue  chan func()
}

// New creates a new Notifier.
func New(cfg config.DiscordConfig) *Notifier {
	n := &Notifier{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		queue: make(chan func(), 100),
	}

	// Start async worker
	go n.worker()

	return n
}

func (n *Notifier) worker() {
	for fn := range n.queue {
		fn()
		// Respect Discord rate limits — minimum 500ms between sends
		time.Sleep(500 * time.Millisecond)
	}
}

// SendStatus sends a status update notification.
func (n *Notifier) SendStatus(title, message string, fields map[string]string) {
	if !n.cfg.Enabled {
		return
	}

	embed := discordEmbed{
		Title:       title,
		Description: message,
		Color:       ColorStatus,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Footer:      &discordEmbedFooter{Text: "ReconX"},
	}

	for k, v := range fields {
		embed.Fields = append(embed.Fields, discordEmbedField{
			Name:   k,
			Value:  v,
			Inline: true,
		})
	}

	n.sendAsync("status", discordPayload{Embeds: []discordEmbed{embed}})
}

// SendCriticalFinding sends a critical vulnerability finding notification.
func (n *Notifier) SendCriticalFinding(target, templateID, name, severity, matchedAt string) {
	if !n.cfg.Enabled {
		return
	}

	color := ColorHigh
	switch strings.ToLower(severity) {
	case "critical":
		color = ColorCritical
	case "high":
		color = ColorHigh
	case "medium":
		color = ColorMedium
	case "low":
		color = ColorLow
	}

	embed := discordEmbed{
		Title:       fmt.Sprintf("🔴 %s — %s", strings.ToUpper(severity), name),
		Description: fmt.Sprintf("Vulnerability found on **%s**", target),
		Color:       color,
		Fields: []discordEmbedField{
			{Name: "Template", Value: fmt.Sprintf("`%s`", templateID), Inline: true},
			{Name: "Severity", Value: strings.ToUpper(severity), Inline: true},
			{Name: "Matched At", Value: truncate(matchedAt, 1024)},
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Footer:    &discordEmbedFooter{Text: "ReconX"},
	}

	n.sendAsync("critical", discordPayload{Embeds: []discordEmbed{embed}})
}

// SendFindingsSummary sends a batch summary of findings for a target.
func (n *Notifier) SendFindingsSummary(target, scanType string, findings []map[string]string) {
	if !n.cfg.Enabled || len(findings) == 0 {
		return
	}

	var lines []string
	for i, f := range findings {
		if i >= 15 {
			lines = append(lines, fmt.Sprintf("... and %d more", len(findings)-15))
			break
		}
		lines = append(lines, fmt.Sprintf("• `%s` — %s", f["template_id"], truncate(f["matched_at"], 200)))
	}

	embed := discordEmbed{
		Title:       fmt.Sprintf("📊 %s Scan Complete: %s", scanType, target),
		Description: fmt.Sprintf("**%d unique findings:**\n%s", len(findings), strings.Join(lines, "\n")),
		Color:       ColorCritical,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Footer:      &discordEmbedFooter{Text: "ReconX"},
	}

	n.sendAsync("critical", discordPayload{Embeds: []discordEmbed{embed}})
}

// SendCycleStart sends a cycle start notification.
func (n *Notifier) SendCycleStart(cycle, totalTargets int) {
	n.SendStatus(
		fmt.Sprintf("🚀 Cycle #%d Started", cycle),
		"Parallel pipeline running — Recon + Scan simultaneously",
		map[string]string{
			"Targets": fmt.Sprintf("%d", totalTargets),
			"Mode":    "Parallel Pipeline",
		},
	)
}

// SendCycleComplete sends a cycle completion notification.
func (n *Notifier) SendCycleComplete(cycle int, stats map[string]int) {
	fields := make(map[string]string)
	for k, v := range stats {
		fields[k] = fmt.Sprintf("%d", v)
	}

	n.SendStatus(
		fmt.Sprintf("🏁 Cycle #%d Complete", cycle),
		"All targets processed. Restarting fresh...",
		fields,
	)
}

func (n *Notifier) sendAsync(webhookKey string, payload discordPayload) {
	n.queue <- func() {
		n.send(webhookKey, payload)
	}
}

func (n *Notifier) send(webhookKey string, payload discordPayload) {
	// Try specific webhook first, then "all" fallback
	url := n.cfg.Webhooks[webhookKey]
	if url == "" {
		url = n.cfg.Webhooks["all"]
	}
	if url == "" {
		return
	}

	data, err := json.Marshal(payload)
	if err != nil {
		slog.Error("failed to marshal discord payload", "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		slog.Error("failed to create discord request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		slog.Error("discord webhook failed", "error", err, "webhook", webhookKey)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		// Rate limited — wait and retry once
		slog.Warn("discord rate limited, waiting 2s")
		time.Sleep(2 * time.Second)
		resp2, err := n.client.Do(req)
		if err == nil {
			resp2.Body.Close()
		}
		return
	}

	if resp.StatusCode >= 400 {
		slog.Error("discord webhook error", "status", resp.StatusCode, "webhook", webhookKey)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
