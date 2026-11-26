package live

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEventJSONOmitsTokenFields(t *testing.T) {
	raw, err := json.Marshal(Event{Type: "log", ScanID: "scan-1", Log: &LogEntry{Level: "info", Message: "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "token") {
		t.Fatalf("event json leaked token field: %s", raw)
	}
}

func TestHubWatchFiltersByScan(t *testing.T) {
	h := New(nil)
	ch, unsub := h.Watch("abc")
	defer unsub()

	h.dispatch(Event{Type: "scan", ScanID: "other", Status: "RUNNING"})
	h.dispatch(Event{Type: "scan", ScanID: "abc", Status: "RUNNING"})

	select {
	case ev := <-ch:
		if ev.ScanID != "abc" || ev.Status != "RUNNING" {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for matching event")
	}
	select {
	case ev := <-ch:
		t.Fatalf("got extra event: %+v", ev)
	default:
	}
}
