package scan

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"bugcode-shield/internal/auth"
	"bugcode-shield/internal/httputil"
	"bugcode-shield/internal/live"

	"github.com/gorilla/websocket"
)

const (
	wsPingInterval = 20 * time.Second
	wsPongWait     = 60 * time.Second
	wsWriteWait    = 8 * time.Second
	wsPollEvery    = 2 * time.Second
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return allowedWSOrigin(r.Header.Get("Origin"))
	},
}

func allowedWSOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "localhost" || host == "127.0.0.1"
}

func bearerOrQueryToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return strings.TrimSpace(r.URL.Query().Get("token"))
}

func isFinished(status string) bool {
	return status == "COMPLETED" || status == "FAILED" || status == "CANCELLED"
}

func (s *Service) Stream(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	userID, err := s.auth.ParseToken(bearerOrQueryToken(r))
	if err != nil {
		httputil.WriteAppError(w, httputil.ErrUnauthorized)
		return
	}
	r = r.WithContext(auth.WithUserID(r.Context(), userID))
	sc, err := s.loadAuthorized(r)
	if err != nil {
		httputil.WriteAppError(w, err)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadLimit(512)
	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	var writeMu sync.Mutex
	send := func(ev live.Event) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
		return conn.WriteJSON(ev)
	}

	logs, lastLogID, err := s.logsAfter(r.Context(), sc.ID, 0)
	if err != nil {
		return
	}
	if err := send(live.Event{Type: "snapshot", ScanID: sc.ID, Scan: sc, Logs: logs}); err != nil {
		return
	}
	lastStatus := sc.Status
	lastCount := sc.FindingCount
	if isFinished(sc.Status) {
		_ = send(live.Event{Type: "done", ScanID: sc.ID, Status: sc.Status, FindingCount: sc.FindingCount, ErrorMessage: sc.ErrorMessage})
		return
	}

	events, unsub := s.events.Watch(sc.ID)
	defer unsub()

	ticker := time.NewTicker(wsPollEvery)
	defer ticker.Stop()
	ping := time.NewTicker(wsPingInterval)
	defer ping.Stop()

	flush := func() (bool, error) {
		finished, err := s.pushUpdates(r.Context(), send, sc.ID, &lastLogID, &lastStatus, &lastCount)
		return finished, err
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case <-readDone:
			return
		case <-events:
			finished, err := flush()
			if err != nil || finished {
				return
			}
		case <-ticker.C:
			finished, err := flush()
			if err != nil || finished {
				return
			}
		case <-ping.C:
			writeMu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(wsWriteWait))
			writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (s *Service) pushUpdates(ctx context.Context, send func(live.Event) error, scanID string, lastLogID *int64, lastStatus *string, lastCount *int) (bool, error) {
	sc, err := s.getByID(ctx, scanID)
	if err != nil {
		return false, err
	}
	logs, maxID, err := s.logsAfter(ctx, scanID, *lastLogID)
	if err != nil {
		return false, err
	}
	for i := range logs {
		if err := send(live.Event{Type: "log", ScanID: scanID, Log: &logs[i]}); err != nil {
			return false, err
		}
	}
	if maxID > *lastLogID {
		*lastLogID = maxID
	}
	if sc.Status != *lastStatus || sc.FindingCount != *lastCount {
		*lastStatus = sc.Status
		*lastCount = sc.FindingCount
		if err := send(live.Event{
			Type:         "scan",
			ScanID:       scanID,
			Status:       sc.Status,
			FindingCount: sc.FindingCount,
			ErrorMessage: sc.ErrorMessage,
		}); err != nil {
			return false, err
		}
	}
	if isFinished(sc.Status) {
		if err := send(live.Event{Type: "done", ScanID: scanID, Status: sc.Status, FindingCount: sc.FindingCount, ErrorMessage: sc.ErrorMessage}); err != nil {
			return true, err
		}
		return true, nil
	}
	return false, nil
}

func (s *Service) getByID(ctx context.Context, scanID string) (Scan, error) {
	var sc Scan
	err := s.pool.QueryRow(ctx, `
		SELECT s.id::text, s.project_id::text, s.source_id::text, s.status, s.scanners, s.error_message, s.started_at, s.finished_at, s.created_at,
			(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id),
			src.kind, src.version_label, src.github_repo, src.local_path
		FROM scans s
		JOIN project_sources src ON src.id = s.source_id
		WHERE s.id=$1
	`, scanID).Scan(&sc.ID, &sc.ProjectID, &sc.SourceID, &sc.Status, &sc.Scanners, &sc.ErrorMessage, &sc.StartedAt, &sc.FinishedAt, &sc.CreatedAt, &sc.FindingCount, &sc.SourceKind, &sc.SourceLabel, &sc.GitHubRepo, &sc.LocalPath)
	return sc, err
}

func (s *Service) logsAfter(ctx context.Context, scanID string, afterID int64) ([]live.LogEntry, int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, scanner, level, message, created_at
		FROM scan_logs WHERE scan_id=$1 AND id>$2 ORDER BY id ASC
	`, scanID, afterID)
	if err != nil {
		return nil, afterID, err
	}
	defer rows.Close()
	items := make([]live.LogEntry, 0)
	maxID := afterID
	for rows.Next() {
		var entry live.LogEntry
		if err := rows.Scan(&entry.ID, &entry.Scanner, &entry.Level, &entry.Message, &entry.CreatedAt); err != nil {
			return nil, afterID, err
		}
		items = append(items, entry)
		if entry.ID > maxID {
			maxID = entry.ID
		}
	}
	return items, maxID, rows.Err()
}

func (s *Service) notify(ctx context.Context, scanID string, kind string) {
	if s.events == nil || scanID == "" {
		return
	}
	s.events.Publish(ctx, live.Event{Type: kind, ScanID: scanID})
}
