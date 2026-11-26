package live

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const Channel = "bugcodeshield:scan-events"

type LogEntry struct {
	ID        int64     `json:"-"`
	Scanner   *string   `json:"scanner"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type Event struct {
	Type         string    `json:"type"`
	ScanID       string    `json:"scan_id"`
	Status       string    `json:"status,omitempty"`
	FindingCount int       `json:"finding_count"`
	ErrorMessage *string   `json:"error_message,omitempty"`
	Log          *LogEntry `json:"log,omitempty"`
	Scan         any       `json:"scan,omitempty"`
	Logs         any       `json:"logs,omitempty"`
}

type Hub struct {
	rdb  *redis.Client
	mu   sync.Mutex
	subs map[string]map[chan Event]struct{}
}

func New(rdb *redis.Client) *Hub {
	return &Hub{rdb: rdb, subs: make(map[string]map[chan Event]struct{})}
}

func (h *Hub) Publish(ctx context.Context, ev Event) {
	if h == nil || h.rdb == nil || ev.ScanID == "" {
		return
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return
	}
	if err := h.rdb.Publish(ctx, Channel, payload).Err(); err != nil {
		slog.Debug("scan event publish skipped", "scan_id", ev.ScanID)
	}
}

func (h *Hub) Watch(scanID string) (<-chan Event, func()) {
	ch := make(chan Event, 32)
	if h == nil {
		return ch, func() {}
	}
	h.mu.Lock()
	if h.subs[scanID] == nil {
		h.subs[scanID] = make(map[chan Event]struct{})
	}
	h.subs[scanID][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.subs[scanID], ch)
		if len(h.subs[scanID]) == 0 {
			delete(h.subs, scanID)
		}
	}
}

func (h *Hub) Serve(ctx context.Context) {
	if h == nil || h.rdb == nil {
		return
	}
	for ctx.Err() == nil {
		if err := h.consume(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("scan event subscribe retrying", "error", err)
			time.Sleep(2 * time.Second)
		}
	}
}

func (h *Hub) consume(ctx context.Context) error {
	sub := h.rdb.Subscribe(ctx, Channel)
	defer sub.Close()
	if _, err := sub.Receive(ctx); err != nil {
		return err
	}
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				return fmt.Errorf("redis subscription closed")
			}
			var ev Event
			if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil || ev.ScanID == "" {
				continue
			}
			h.dispatch(ev)
		}
	}
}

func (h *Hub) dispatch(ev Event) {
	h.mu.Lock()
	clients := make([]chan Event, 0, len(h.subs[ev.ScanID]))
	for ch := range h.subs[ev.ScanID] {
		clients = append(clients, ch)
	}
	h.mu.Unlock()
	for _, ch := range clients {
		select {
		case ch <- ev:
		default:
		}
	}
}
