package management

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type persistedHealth struct {
	Schema       int               `json:"schema"`
	Endpoint     string            `json:"endpoint_id"`
	Identity     string            `json:"identity_id"`
	Samples      []map[string]any  `json:"samples"`
	Changes      []map[string]any  `json:"changes"`
	Interfaces   string            `json:"interfaces"`
	Observations map[string]string `json:"observations"`
}

func loadHealthLocked(c Config) {
	if healthHistory.root == c.Root {
		return
	}
	healthHistory.root = c.Root
	healthHistory.endpoint = c.Endpoint
	healthHistory.identity = c.Identity
	healthHistory.samples = nil
	healthHistory.changes = nil
	healthHistory.interfaces = ""
	healthHistory.observations = map[string]string{}
	healthHistory.sampled = time.Time{}
	healthHistory.persisted = time.Time{}
	b, e := readBounded(filepath.Join(c.Root, "health-history.json"), 512<<10)
	if e != nil {
		return
	}
	var saved persistedHealth
	if json.Unmarshal(b, &saved) != nil || saved.Schema != 1 || saved.Endpoint != c.Endpoint || saved.Identity != c.Identity || len(saved.Samples) > 120 || len(saved.Changes) > 32 || len(saved.Observations) > 16 {
		return
	}
	healthHistory.samples = saved.Samples
	healthHistory.changes = saved.Changes
	healthHistory.interfaces = saved.Interfaces
	healthHistory.observations = saved.Observations
	if healthHistory.observations == nil {
		healthHistory.observations = map[string]string{}
	}
	// OS counters may reset after reboot; the next two new samples establish a fresh rate.
	if len(healthHistory.samples) > 0 {
		for _, key := range []string{"cpu_total_ticks", "cpu_idle_ticks"} {
			delete(healthHistory.samples[len(healthHistory.samples)-1], key)
		}
	}
}
func persistHealthLocked(force bool) {
	if healthHistory.root == "" || (!force && time.Since(healthHistory.persisted) < time.Minute) {
		return
	}
	healthHistory.persistenceError = "Recent history could not be persisted; earlier durable data retained"
	saved := persistedHealth{1, healthHistory.endpoint, healthHistory.identity, healthHistory.samples, healthHistory.changes, healthHistory.interfaces, healthHistory.observations}
	b, e := json.Marshal(saved)
	for e == nil && len(b) > 512<<10 && len(saved.Samples) > 1 {
		saved.Samples = saved.Samples[1:]
		b, e = json.Marshal(saved)
	}
	for e == nil && len(b) > 512<<10 && len(saved.Changes) > 0 {
		saved.Changes = saved.Changes[1:]
		b, e = json.Marshal(saved)
	}
	if e != nil || len(b) > 512<<10 {
		return
	}
	f, e := os.CreateTemp(healthHistory.root, "health-history-")
	if e != nil {
		return
	}
	path := f.Name()
	defer os.Remove(path)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return
	}
	if replaceFile(path, filepath.Join(healthHistory.root, "health-history.json")) == nil {
		healthHistory.persisted = time.Now()
		healthHistory.samples = saved.Samples
		healthHistory.changes = saved.Changes
		healthHistory.persistenceError = ""
	}
}
func normalizedObservation(value string) string {
	var v any
	if json.Unmarshal([]byte(value), &v) == nil {
		v = normalizeInventory(v)
		b, _ := json.Marshal(v)
		return string(b)
	}
	rows := strings.Split(strings.TrimSpace(value), "\n")
	for i := range rows {
		rows[i] = strings.Join(strings.Fields(rows[i]), " ")
	}
	sort.Strings(rows)
	if len(rows) > 500 {
		rows = append(rows[:500], "[coverage limited to 500 sorted rows]")
	}
	return strings.Join(rows, "\n")
}
func normalizeInventory(value any) any {
	switch v := value.(type) {
	case []any:
		for i := range v {
			v[i] = normalizeInventory(v[i])
		}
		sort.Slice(v, func(i, j int) bool {
			a, _ := json.Marshal(v[i])
			b, _ := json.Marshal(v[j])
			return string(a) < string(b)
		})
		if len(v) > 500 {
			return append(v[:500], map[string]any{"coverage": "first 500 sorted records"})
		}
		return v
	case map[string]any:
		for k, a := range v {
			if k == "output" {
				if text, ok := a.(string); ok {
					v[k] = normalizedObservation(text)
					continue
				}
			}
			v[k] = normalizeInventory(a)
		}
		return v
	default:
		return v
	}
}
func refreshHealthObservations(ctx context.Context, j Job, c Config) map[string]string {
	outcomes := map[string]string{}
	budget, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for _, action := range []string{"services.list", "packages.list"} {
		sub := j
		sub.Action = action
		sub.Params = map[string]json.RawMessage{}
		step, stop := context.WithTimeout(budget, 20*time.Second)
		result := executeJob(step, sub, c)
		stop()
		outcomes[action] = result.State
		if result.State == "completed" {
			recordToolObservation(action, result.Output)
		}
	}
	step, stop := context.WithTimeout(budget, 20*time.Second)
	startup := startupObservation(step, c)
	stop()
	outcomes["startup"] = startup.State
	if startup.State == "completed" {
		recordToolObservation("startup", startup.Output)
	}
	healthHistory.Lock()
	persistHealthLocked(true)
	healthHistory.Unlock()
	return outcomes
}
