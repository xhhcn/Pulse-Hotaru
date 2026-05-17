package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestSaveClientPushBatch verifies the batch persistence path that replaces
// the old "1 + N + (Get + Upsert)" sequence in handleClientPush. The whole
// point of the batch is to compress what used to be ~8 fsyncs per push
// into 1, and to leave the on-disk state semantically identical to what
// the old per-result loop produced.
//
// This test is fast, deterministic, and dependency-free (no real DB
// fixture required) so it runs in CI.
func TestSaveClientPushBatch(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "metrics.db")

	s, err := NewStore(tmp)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Second)
	metric := SystemMetric{
		ID:        "node-1",
		Name:      "node-1",
		CPU:       12.5,
		Memory:    44.0,
		UpdatedAt: now,
		TCPingData: map[string]TCPingTargetData{
			"1.1.1.1:443": {Latency: 11.2, Timestamp: now},
		},
	}
	results := []TCPingResult{
		{ClientID: "node-1", Target: "1.1.1.1:443", Latency: ptrFloat64(11.2), Timestamp: now},
		{ClientID: "node-1", Target: "8.8.8.8:53", Latency: ptrFloat64(20.4), Timestamp: now},
		{ClientID: "node-1", Target: "9.9.9.9:53", Latency: nil, Timestamp: now}, // failed measurement
	}
	if err := s.SaveClientPushBatch(metric, results); err != nil {
		t.Fatalf("SaveClientPushBatch: %v", err)
	}

	got, err := s.Get("node-1")
	if err != nil || got == nil {
		t.Fatalf("Get after batch: err=%v got=%v", err, got)
	}
	if got.CPU != 12.5 || got.Memory != 44.0 {
		t.Errorf("metric fields wrong: %+v", got)
	}
	if len(got.TCPingData) != 1 {
		t.Errorf("TCPingData should still have 1 entry, got %d", len(got.TCPingData))
	}

	hist, err := s.GetTCPingResults("node-1")
	if err != nil {
		t.Fatalf("GetTCPingResults: %v", err)
	}
	if len(hist) != 3 {
		t.Errorf("expected 3 history rows, got %d", len(hist))
	}

	// Sanity: an empty-results push must still persist the metric, not error.
	metric.CPU = 99.0
	if err := s.SaveClientPushBatch(metric, nil); err != nil {
		t.Fatalf("SaveClientPushBatch with nil results: %v", err)
	}
	got2, _ := s.Get("node-1")
	if got2.CPU != 99.0 {
		t.Errorf("metric not updated by empty-results push: got %.1f", got2.CPU)
	}
}

func ptrFloat64(v float64) *float64 { return &v }

// TestSaveClientPushBatchReducesAllocations is a soft, informational
// benchmark-style test: it measures the heap delta of 1000 push batches
// (3 results each) and just logs the per-push cost. This is purely
// observational — it asserts no growth bound, only fails if the path
// blows up. It exists so operators can sanity-check that the batch path
// is not silently leaking memory in the steady state.
func TestSaveClientPushBatchSteadyHeap(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "metrics.db")

	s, err := NewStore(tmp)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer s.Close()

	const N = 1000
	now := time.Now().UTC().Truncate(time.Second)
	results := []TCPingResult{
		{ClientID: "n", Target: "1.1.1.1:443", Latency: ptrFloat64(10), Timestamp: now},
		{ClientID: "n", Target: "8.8.8.8:53", Latency: ptrFloat64(20), Timestamp: now},
		{ClientID: "n", Target: "9.9.9.9:53", Latency: ptrFloat64(30), Timestamp: now},
	}

	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)

	for i := 0; i < N; i++ {
		m := SystemMetric{ID: "n", Name: "n", CPU: float64(i % 100), UpdatedAt: time.Now().UTC()}
		// Use unique timestamps so each batch writes new tcping rows.
		for j := range results {
			results[j].Timestamp = now.Add(time.Duration(i) * time.Second)
		}
		if err := s.SaveClientPushBatch(m, results); err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&m1)
	delta := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	t.Logf("%d push batches → HeapAlloc delta %d bytes (%.2f KB)", N, delta, float64(delta)/1024)

	// Sanity check: 1000 pushes × 3 results ≈ 3000 rows. Each row is ~150
	// bytes JSON, all stored in mmap-backed bbolt pages, NOT Go heap.
	// HeapAlloc delta should be well under a few MB.
	if delta > 50*1024*1024 {
		st, _ := os.Stat(tmp)
		var dbSize int64
		if st != nil {
			dbSize = st.Size()
		}
		t.Errorf("heap delta unexpectedly large: %d bytes (db file size %d)", delta, dbSize)
	}

	// Confirm history is queryable and bounded by the 24h-window logic.
	hist, err := s.GetTCPingResults("n")
	if err != nil {
		t.Fatalf("GetTCPingResults: %v", err)
	}
	t.Logf("rows visible in 24h window: %d", len(hist))
	if len(hist) == 0 {
		t.Errorf("expected some history rows in the 24h window")
	}
}

// TestSaveClientPushBatchConcurrent makes sure the batch path is safe for
// concurrent callers (each push is a separate goroutine in real life via
// the HTTP server). bbolt serialises Updates internally, so this is
// primarily a fuzz against any locking we add later.
func TestSaveClientPushBatchConcurrent(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "metrics.db")

	s, err := NewStore(tmp)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer s.Close()

	const G = 20
	const PERG = 50
	done := make(chan error, G)
	now := time.Now().UTC().Truncate(time.Second)
	for g := 0; g < G; g++ {
		go func(g int) {
			id := fmt.Sprintf("c-%d", g)
			for i := 0; i < PERG; i++ {
				m := SystemMetric{ID: id, Name: id, CPU: float64(i), UpdatedAt: time.Now().UTC()}
				rs := []TCPingResult{
					{ClientID: id, Target: "1.1.1.1:443", Latency: ptrFloat64(5), Timestamp: now.Add(time.Duration(i) * time.Second)},
					{ClientID: id, Target: "8.8.8.8:53", Latency: ptrFloat64(7), Timestamp: now.Add(time.Duration(i) * time.Second)},
				}
				if err := s.SaveClientPushBatch(m, rs); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}(g)
	}
	for i := 0; i < G; i++ {
		if err := <-done; err != nil {
			t.Fatalf("goroutine err: %v", err)
		}
	}

	// Every client's latest metric must be visible.
	for g := 0; g < G; g++ {
		id := fmt.Sprintf("c-%d", g)
		m, err := s.Get(id)
		if err != nil || m == nil {
			t.Errorf("missing %s: err=%v", id, err)
		}
	}
}
