package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"bugcode-shield/internal/platform"
)

type Status string

const (
	StatusOK   Status = "ok"
	StatusDown Status = "down"
)

type ServiceStatus struct {
	Status    Status `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

type ReadyReport struct {
	Status   Status                   `json:"status"`
	Version  string                   `json:"version"`
	Services map[string]ServiceStatus `json:"services"`
}

type Checker struct {
	clients *platform.Clients
	timeout time.Duration
}

func New(clients *platform.Clients) *Checker {
	return &Checker{clients: clients, timeout: 2 * time.Second}
}

func (c *Checker) Live() map[string]string {
	return map[string]string{
		"status":  string(StatusOK),
		"service": "bugcodeshield-api",
		"version": c.clients.Config().AppVersion,
	}
}

func (c *Checker) Ready(parent context.Context) ReadyReport {
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()

	checks := map[string]func(context.Context) error{
		"postgres": c.clients.PingPostgres,
		"redis":    c.clients.PingRedis,
		"rabbitmq": c.clients.PingRabbitMQ,
		"minio":    c.clients.PingMinIO,
	}

	services := make(map[string]ServiceStatus, len(checks))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for name, ping := range checks {
		wg.Add(1)
		go func(name string, ping func(context.Context) error) {
			defer wg.Done()
			start := time.Now()
			err := ping(ctx)
			result := ServiceStatus{
				Status:    StatusOK,
				LatencyMS: time.Since(start).Milliseconds(),
			}
			if err != nil {
				result.Status = StatusDown
				result.Error = "unreachable"
			}
			mu.Lock()
			services[name] = result
			mu.Unlock()
		}(name, ping)
	}
	wg.Wait()

	report := ReadyReport{
		Status:   StatusOK,
		Version:  c.clients.Config().AppVersion,
		Services: services,
	}
	for _, svc := range services {
		if svc.Status != StatusOK {
			report.Status = StatusDown
			break
		}
	}
	return report
}

func (c *Checker) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := c.Ready(r.Context())
		status := http.StatusOK
		if report.Status != StatusOK {
			status = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(report)
	}
}
