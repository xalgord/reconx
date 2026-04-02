package dashboard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/reconx/internal/config"
	"github.com/xalgord/reconx/internal/findings"
	"github.com/xalgord/reconx/internal/state"
	"github.com/xalgord/reconx/web"
)

// session store (in-memory, simple)
var sessions = make(map[string]sessionData)

type sessionData struct {
	Username  string
	ExpiresAt time.Time
}

// Dashboard serves the web UI and API.
type Dashboard struct {
	cfg      *config.DashboardConfig
	state    *state.Manager
	store    *findings.Store
	logFile  string
	tmpl     *template.Template
	mux      *http.ServeMux
}

// New creates a new Dashboard server.
func New(cfg *config.DashboardConfig, st *state.Manager, store *findings.Store, logFile string) *Dashboard {
	d := &Dashboard{
		cfg:     cfg,
		state:   st,
		store:   store,
		logFile: logFile,
		mux:     http.NewServeMux(),
	}

	// Parse templates from embedded FS
	var err error
	d.tmpl, err = template.ParseFS(web.Templates, "templates/*.html")
	if err != nil {
		slog.Error("failed to parse templates", "error", err)
	}

	// Register routes
	d.mux.HandleFunc("/", d.requireAuth(d.handleIndex))
	d.mux.HandleFunc("/login", d.handleLogin)
	d.mux.HandleFunc("/logout", d.handleLogout)
	d.mux.HandleFunc("/api/status", d.requireAuth(d.handleAPIStatus))
	d.mux.HandleFunc("/api/findings", d.requireAuth(d.handleAPIFindings))
	d.mux.HandleFunc("/api/stats", d.requireAuth(d.handleAPIStats))
	d.mux.HandleFunc("/api/categories", d.requireAuth(d.handleAPICategories))
	d.mux.HandleFunc("/api/logs", d.requireAuth(d.handleAPILogs))
	d.mux.HandleFunc("/api/findings/delete", d.requireAuth(d.handleAPIDeleteFindings))

	// Static files — serve from embedded FS
	staticSub, _ := fs.Sub(web.Static, "static")
	d.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	return d
}

// ListenAndServe starts the dashboard server.
func (d *Dashboard) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port)
	slog.Info("dashboard starting", "address", addr)

	server := &http.Server{
		Addr:         addr,
		Handler:      d.mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server.ListenAndServe()
}

// --- Auth Middleware ---

func (d *Dashboard) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("reconx_session")
		if err != nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}

		sess, ok := sessions[cookie.Value]
		if !ok || time.Now().After(sess.ExpiresAt) {
			delete(sessions, cookie.Value)
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}

		next(w, r)
	}
}

func (d *Dashboard) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		d.tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == d.cfg.Username && password == d.cfg.Password {
		token := generateToken()
		sessions[token] = sessionData{
			Username:  username,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "reconx_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400,
			SameSite: http.SameSiteStrictMode,
		})

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	d.tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
}

func (d *Dashboard) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("reconx_session")
	if err == nil {
		delete(sessions, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "reconx_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/login", http.StatusFound)
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	d.tmpl.ExecuteTemplate(w, "index.html", nil)
}

// --- API Handlers ---

func (d *Dashboard) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	st := d.state.GetState()

	var uptime string
	if st.StartedAt != "" {
		if start, err := time.Parse(time.RFC3339, st.StartedAt); err == nil {
			delta := time.Since(start)
			days := int(delta.Hours()) / 24
			hours := int(delta.Hours()) % 24
			mins := int(delta.Minutes()) % 60
			uptime = fmt.Sprintf("%dd %dh %dm", days, hours, mins)
		}
	}

	var progress float64
	if st.TotalTargets > 0 {
		progress = float64(st.ScanCompleted) / float64(st.TotalTargets) * 100
	}

	writeJSON(w, map[string]interface{}{
		"cycle":                st.Cycle,
		"phase":                st.Phase,
		"current_target":       st.CurrentTarget,
		"current_target_index": st.CurrentTargetIndex,
		"total_targets":        st.TotalTargets,
		"recon_completed":      st.ReconCompleted,
		"scan_completed":       st.ScanCompleted,
		"progress":             fmt.Sprintf("%.1f", progress),
		"started_at":           st.StartedAt,
		"last_update":          st.LastUpdate,
		"uptime":               uptime,
		"findings_count":       st.FindingsCount,
		"subdomains_found":     st.SubdomainsFound,
		"live_hosts_found":     st.LiveHostsFound,
		"status_message":       st.StatusMessage,
	})
}

func (d *Dashboard) handleAPIFindings(w http.ResponseWriter, r *http.Request) {
	st := d.state.GetState()

	opts := findings.QueryOpts{
		Cycle:       st.Cycle,
		Severity:    r.URL.Query().Get("severity"),
		ScanType:    r.URL.Query().Get("scan_type"),
		Domain:      r.URL.Query().Get("domain"),
		TemplateID:  r.URL.Query().Get("category"),
		ShowHistory: r.URL.Query().Get("history") == "true",
		Page:        getIntParam(r, "page", 1),
		PerPage:     getIntParam(r, "per_page", 50),
	}

	if cycleStr := r.URL.Query().Get("cycle"); cycleStr != "" {
		if c, err := strconv.Atoi(cycleStr); err == nil {
			opts.Cycle = c
		}
	}

	result := d.store.Query(opts)
	writeJSON(w, result)
}

func (d *Dashboard) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	st := d.state.GetState()
	showHistory := r.URL.Query().Get("history") == "true"

	stats := d.store.GetStats(st.Cycle, showHistory)

	writeJSON(w, map[string]interface{}{
		"total_findings":       stats.Total,
		"all_time_findings":    stats.AllTimeTotal,
		"severity_counts":      stats.SeverityCounts,
		"unique_hosts_affected": len(stats.UniqueHosts),
		"unique_cves_found":    len(stats.UniqueCVEs),
		"current_cycle":        st.Cycle,
		"subdomains_found":     st.SubdomainsFound,
		"live_hosts_found":     st.LiveHostsFound,
		"showing_history":      showHistory,
	})
}

func (d *Dashboard) handleAPICategories(w http.ResponseWriter, r *http.Request) {
	st := d.state.GetState()
	showHistory := r.URL.Query().Get("history") == "true"

	cats := d.store.GetCategories(st.Cycle, showHistory)
	writeJSON(w, cats)
}

func (d *Dashboard) handleAPILogs(w http.ResponseWriter, r *http.Request) {
	lines := readLastLines(d.logFile, 100)
	writeJSON(w, lines)
}

func (d *Dashboard) handleAPIDeleteFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type  string `json:"type"`
		Cycle int    `json:"cycle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	switch req.Type {
	case "all":
		d.store.DeleteAll()
		writeJSON(w, map[string]interface{}{"success": true})
	case "cycle":
		deleted, err := d.store.DeleteByCycle(req.Cycle)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]interface{}{"success": true, "deleted": deleted})
	default:
		http.Error(w, `{"error":"invalid delete type"}`, http.StatusBadRequest)
	}
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func getIntParam(r *http.Request, key string, defaultVal int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func readLastLines(filePath string, n int) []string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	// Remove empty trailing line
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	return lines
}
