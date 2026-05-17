package main

import (
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TestPruneAndCompactRealDB exercises the orphan-bucket prune + compaction
// path on a copy of a real metrics.db. The fixture path is supplied via
// PULSE_REAL_DB_FIXTURE so the test is skipped automatically in CI (where
// no fixture exists) but runs end-to-end against the operator's actual
// data when invoked locally.
//
// Run:
//
//	PULSE_REAL_DB_FIXTURE=/path/to/metrics.db go test -run TestPruneAndCompactRealDB -v ./...
func TestPruneAndCompactRealDB(t *testing.T) {
	src := os.Getenv("PULSE_REAL_DB_FIXTURE")
	if src == "" {
		t.Skip("PULSE_REAL_DB_FIXTURE not set; skipping real-DB migration test")
	}
	if _, err := os.Stat(src); err != nil {
		t.Skipf("PULSE_REAL_DB_FIXTURE=%s not readable: %v", src, err)
	}

	tmpDir := t.TempDir()
	dstPath := tmpDir + "/metrics.db"
	if err := copyFile(src, dstPath); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	beforeSize := fileSize(t, dstPath)
	t.Logf("DB size BEFORE NewStore: %d bytes (%.1f MB)", beforeSize, float64(beforeSize)/1024/1024)

	// --- 1. List buckets before NewStore ---
	beforeBuckets := map[string]int{}
	{
		db, err := openBolt(dstPath)
		if err != nil {
			t.Fatalf("open fixture: %v", err)
		}
		_ = db.View(func(tx *bolt.Tx) error {
			return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
				beforeBuckets[string(name)] = b.Stats().KeyN
				return nil
			})
		})
		_ = db.Close()
	}
	t.Logf("Buckets BEFORE: %+v", beforeBuckets)

	// --- 2. Run NewStore (the actual production path). Measure wall time
	//        and RSS so we have a concrete number to show. ---
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	t0 := time.Now()
	store, err := NewStore(dstPath)
	openWall := time.Since(t0)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	t.Logf("NewStore wall=%v   heap_alloc Δ=%+d KB   sys=%d MB",
		openWall,
		(int64(memAfter.HeapAlloc)-int64(memBefore.HeapAlloc))/1024,
		memAfter.Sys/1024/1024,
	)

	// --- 3. List buckets after NewStore ---
	afterBuckets := map[string]int{}
	_ = store.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			afterBuckets[string(name)] = b.Stats().KeyN
			return nil
		})
	})
	t.Logf("Buckets AFTER:  %+v", afterBuckets)

	// --- 4. Assert: every known bucket survives; every orphan is gone. ---
	for known := range knownBuckets {
		if _, ok := afterBuckets[known]; !ok {
			t.Errorf("known bucket %q missing after NewStore", known)
		}
	}
	for name := range afterBuckets {
		if _, ok := knownBuckets[name]; !ok {
			t.Errorf("orphan bucket %q SURVIVED prune", name)
		}
	}

	// --- 5. Pick a random client_id from `systems` and query its tcping
	//        history. This exercises the new GetTCPingResults prefix-filter
	//        path on the real data. ---
	var sampleClientID string
	_ = store.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()
		k, _ := c.First()
		if k != nil {
			sampleClientID = string(k)
		}
		return nil
	})
	if sampleClientID != "" {
		runtime.GC()
		runtime.ReadMemStats(&memBefore)
		t0 = time.Now()
		results, err := store.GetTCPingResults(sampleClientID)
		qWall := time.Since(t0)
		runtime.GC()
		runtime.ReadMemStats(&memAfter)
		if err != nil {
			t.Errorf("GetTCPingResults(%s): %v", sampleClientID, err)
		} else {
			t.Logf("GetTCPingResults(client_id=%s) wall=%v results=%d   heap_alloc Δ=%+d KB   sys=%d MB",
				sampleClientID,
				qWall,
				len(results),
				(int64(memAfter.HeapAlloc)-int64(memBefore.HeapAlloc))/1024,
				memAfter.Sys/1024/1024,
			)
		}
	}

	// --- 6. Close + report final file size ---
	if err := store.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	afterSize := fileSize(t, dstPath)
	t.Logf("DB size AFTER NewStore: %d bytes (%.1f MB) — shrunk by %.1f MB",
		afterSize,
		float64(afterSize)/1024/1024,
		float64(beforeSize-afterSize)/1024/1024,
	)

	if afterSize >= beforeSize && (len(beforeBuckets) > len(knownBuckets)) {
		t.Errorf("expected file to shrink after pruning orphans + compaction, but it stayed at %d bytes", afterSize)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func fileSize(t *testing.T, p string) int64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return fi.Size()
}
