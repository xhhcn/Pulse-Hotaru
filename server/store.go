package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultDBPath    = "./data/metrics.db"
	bucketName       = "systems"
	tcpingBucket     = "tcping"
	configBucket     = "config"
	configKey        = "tcping"
	navbarConfigKey  = "navbar"
	privacyConfigKey = "privacy"
	authBucket       = "auth"
	passwordKey      = "admin_password"
)

// Store represents the persistent storage
type Store struct {
	db *bolt.DB
}

// openBolt opens the bbolt database with the safer FreelistMapType and a
// slightly more generous lock timeout. FreelistMapType uses a hashmap instead
// of a sorted array for the freelist, which is significantly more robust
// against the freelist-corruption bugs present in older bbolt versions and
// drastically reduces the probability of "invalid freelist page" panics after
// an ungraceful shutdown.
func openBolt(dbPath string) (*bolt.DB, error) {
	return bolt.Open(dbPath, 0600, &bolt.Options{
		Timeout:      5 * time.Second,
		FreelistType: bolt.FreelistMapType,
	})
}

// isDBCorruptionError returns true when the error returned from bolt.Open
// looks like on-disk corruption that cannot be recovered by re-opening.
// We keep the match list intentionally conservative: we only want to auto
// quarantine on errors that are known to be unrecoverable. All other errors
// (timeout, permission denied, ...) are left to bubble up.
func isDBCorruptionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	corruptionSignatures := []string{
		"invalid freelist page",
		"invalid database",
		"meta page",
		"checksum",
		"unexpected EOF",
		"page flags",
		"invalid page type",
		"invalid leaf",
		"invalid branch",
	}
	for _, sig := range corruptionSignatures {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

// quarantineCorruptDB renames the broken file aside with a timestamp suffix so
// that the service can start with a fresh database while still preserving the
// evidence for post-mortem inspection / manual recovery via `bbolt` CLI.
func quarantineCorruptDB(dbPath string, cause error) (string, error) {
	suffix := time.Now().UTC().Format("20060102T150405Z")
	backupPath := fmt.Sprintf("%s.corrupt-%s", dbPath, suffix)
	if err := os.Rename(dbPath, backupPath); err != nil {
		return "", fmt.Errorf("failed to quarantine corrupt database (%v): %w", cause, err)
	}
	// bbolt also creates a .lock file next to the DB on some platforms; make a
	// best-effort cleanup so the fresh DB can acquire the lock.
	_ = os.Remove(dbPath + ".lock")
	return backupPath, nil
}

// NewStore creates or opens the database
func NewStore(dbPath string) (*Store, error) {
	// Use default path if not specified
	if dbPath == "" {
		dbPath = defaultDBPath
	}

	// Create data directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Open database (creates if doesn't exist). If the on-disk file is
	// corrupted (e.g. "invalid freelist page" after an ungraceful shutdown),
	// quarantine it and start over with an empty DB so that the service can
	// still come up. The corrupt file is preserved as <path>.corrupt-<ts> for
	// manual recovery with the `bbolt` CLI.
	db, err := openBolt(dbPath)
	if err != nil {
		if isDBCorruptionError(err) {
			log.Printf("⚠️  Detected corrupt bbolt database at %s: %v", dbPath, err)
			backupPath, qerr := quarantineCorruptDB(dbPath, err)
			if qerr != nil {
				return nil, qerr
			}
			log.Printf("🗂️  Corrupt database moved aside to %s. Starting with a fresh database.", backupPath)
			db, err = openBolt(dbPath)
			if err != nil {
				return nil, fmt.Errorf("failed to open database after quarantine: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to open database: %w", err)
		}
	}

	// Initialize buckets
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(configBucket))
		if err != nil {
			return fmt.Errorf("failed to create config bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(tcpingBucket))
		if err != nil {
			return fmt.Errorf("failed to create tcping bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(authBucket))
		if err != nil {
			return fmt.Errorf("failed to create auth bucket: %w", err)
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	log.Printf("✅ Database initialized: %s", dbPath)

	store := &Store{db: db}

	// Log current data count
	count := store.Count()
	if count == 0 {
		log.Printf("📦 Database is empty - waiting for first metrics")
	} else {
		log.Printf("📊 Loaded %d existing systems from database", count)
	}

	return store, nil
}

// Close closes the database
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Snapshot streams a consistent hot-backup of the entire bbolt database
// to the provided writer. Internally it runs inside a read-only
// transaction (db.View) and delegates to bbolt's built-in Tx.WriteTo,
// which produces a byte-identical copy of the on-disk file as it
// appeared at the moment the transaction began — safe to take while
// the server is live serving traffic, with no downtime and no risk of
// a half-written page ending up in the backup.
//
// The number of bytes written is returned so the caller can set
// Content-Length for streamed HTTP responses.
//
// The resulting file can be used as a drop-in replacement for
// data/metrics.db on a new host: stop the target container, swap the
// file, start it. See scripts/backup.sh and scripts/restore.sh for a
// turnkey migration workflow.
func (s *Store) Snapshot(w io.Writer) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not open")
	}
	var written int64
	err := s.db.View(func(tx *bolt.Tx) error {
		n, werr := tx.WriteTo(w)
		written = n
		return werr
	})
	return written, err
}

// Upsert inserts or updates a system metric
func (s *Store) Upsert(metric SystemMetric) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		// Serialize metric to JSON
		data, err := json.Marshal(metric)
		if err != nil {
			return fmt.Errorf("failed to marshal metric: %w", err)
		}

		// Store with ID as key
		if err := bucket.Put([]byte(metric.ID), data); err != nil {
			return fmt.Errorf("failed to put metric: %w", err)
		}

		return nil
	})
}

// List returns all system metrics sorted by order
func (s *Store) List() ([]SystemMetric, error) {
	metrics := make([]SystemMetric, 0)

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			var metric SystemMetric
			if err := json.Unmarshal(v, &metric); err != nil {
				log.Printf("⚠️ Failed to unmarshal metric %s: %v", string(k), err)
				return nil // Skip corrupted entry
			}
			metrics = append(metrics, metric)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	// Sort by order field (ascending)
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Order < metrics[j].Order
	})

	return metrics, nil
}

// Get retrieves a specific system metric by ID
func (s *Store) Get(id string) (*SystemMetric, error) {
	var metric SystemMetric

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		data := bucket.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("metric not found")
		}

		return json.Unmarshal(data, &metric)
	})

	if err != nil {
		return nil, err
	}

	return &metric, nil
}

// Delete removes a system metric by ID
func (s *Store) Delete(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return bucket.Delete([]byte(id))
	})
}

// Count returns the number of systems in the database
func (s *Store) Count() int {
	count := 0
	s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket != nil {
			count = bucket.Stats().KeyN
		}
		return nil
	})
	return count
}

// DBPath returns the database file path from environment or default
func DBPath() string {
	if path := os.Getenv("DB_PATH"); path != "" {
		return path
	}
	return defaultDBPath
}

// TCPingResult represents a tcping result
type TCPingResult struct {
	ClientID  string    `json:"client_id"`
	Target    string    `json:"target"`  // Target address (e.g., "8.8.8.8:53")
	Latency   *float64  `json:"latency"` // Latency in milliseconds (nil for timeout/failure)
	Timestamp time.Time `json:"timestamp"`
}

// SaveTCPingResult saves a tcping result
func (s *Store) SaveTCPingResult(result TCPingResult) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		// Use timestamp + client_id + target as key for uniqueness
		key := fmt.Sprintf("%d_%s_%s", result.Timestamp.Unix(), result.ClientID, result.Target)
		data, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal tcping result: %w", err)
		}

		return bucket.Put([]byte(key), data)
	})
}

// GetTCPingResults returns all tcping results for a client within 24 hours.
// If target is provided, only returns results for that target.
//
// Uses the same cursor-seek strategy as CleanupOldTCPingResults: keys are
// formatted as "<unix-seconds>_<client>_<target>" with a 10-digit timestamp
// (Unix seconds fit in 10 chars until year 2286), so bbolt's lexicographic
// iteration order matches numeric timestamp order. Seeking directly to the
// cutoff prefix and walking forward avoids unmarshalling potentially hundreds
// of thousands of older records on busy deployments — which is what made
// "open chart" perceptibly slow as the database aged. The `_` separator
// prevents the prefix from accidentally matching a longer timestamp (e.g.
// "1714531200" vs "1714531200_xxx").
//
// Within a single second the suffix order is `<client>_<target>`, so records
// for one client/target chunk together. We still emit a final sort below to
// guarantee strict timestamp ordering across sub-second writes that share a
// timestamp but differ in client / target — which keeps callers free to
// assume the result slice is sorted.
func (s *Store) GetTCPingResults(clientID string, target ...string) ([]TCPingResult, error) {
	results := make([]TCPingResult, 0, 256)
	cutoffTime := time.Now().Add(-24 * time.Hour)
	cutoffPrefix := []byte(fmt.Sprintf("%d_", cutoffTime.Unix()))
	filterTarget := ""
	if len(target) > 0 {
		filterTarget = target[0]
	}

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		c := bucket.Cursor()
		// Seek lands on the smallest key >= cutoffPrefix. Every record
		// from here forward is within the 24-hour window. Records older
		// than the cutoff are skipped entirely without unmarshalling.
		for k, v := c.Seek(cutoffPrefix); k != nil; k, v = c.Next() {
			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				continue // Skip corrupted entry
			}

			if result.ClientID != clientID {
				continue
			}
			if filterTarget != "" && result.Target != filterTarget {
				continue
			}

			// Defensive: if a writer ever bypassed the timestamp-prefix
			// key format, the seek-skip wouldn't catch it. Re-verify the
			// 24-h window from the actual timestamp field. We use
			// `!After(cutoffTime)` (i.e. <=) to preserve the original
			// strict-greater-than semantic of the previous full-scan
			// implementation, so the visible window is unchanged.
			if !result.Timestamp.After(cutoffTime) {
				continue
			}

			results = append(results, result)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Stabilise sub-second-tie ordering for callers that assume strict
	// ascending-by-timestamp. The slice is already nearly sorted, so the
	// constant factor is small.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.Before(results[j].Timestamp)
	})

	return results, nil
}

// DeleteTCPingResultsByTarget deletes all tcping results for a specific target
func (s *Store) DeleteTCPingResultsByTarget(target string) error {
	var keysToDelete [][]byte

	// First pass: collect keys to delete
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				return nil // Skip corrupted entry
			}

			if result.Target == target {
				keysToDelete = append(keysToDelete, k)
			}
			return nil
		})
	})

	if err != nil {
		return err
	}

	// Second pass: delete entries
	if len(keysToDelete) > 0 {
		return s.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte(tcpingBucket))
			if bucket == nil {
				return fmt.Errorf("tcping bucket not found")
			}

			for _, key := range keysToDelete {
				if err := bucket.Delete(key); err != nil {
					return err
				}
			}
			return nil
		})
	}

	return nil
}

// DeleteTCPingResultsByClient deletes all tcping results for a specific client
func (s *Store) DeleteTCPingResultsByClient(clientID string) error {
	var keysToDelete [][]byte

	// First pass: collect keys to delete
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				return nil // Skip corrupted entry
			}

			if result.ClientID == clientID {
				keysToDelete = append(keysToDelete, k)
			}
			return nil
		})
	})

	if err != nil {
		return err
	}

	// Second pass: delete entries
	if len(keysToDelete) > 0 {
		return s.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte(tcpingBucket))
			if bucket == nil {
				return fmt.Errorf("tcping bucket not found")
			}

			for _, key := range keysToDelete {
				if err := bucket.Delete(key); err != nil {
					return err
				}
			}
			return nil
		})
	}

	return nil
}

// CleanupOldTCPingResults removes tcping results older than 24 hours.
//
// Keys are formatted as "<unix-seconds>_<client>_<target>" where the
// timestamp is always 10 digits (Unix seconds fit in 10 characters until
// year 2286), so bbolt's lexicographic iteration order matches numeric
// timestamp order. We therefore seek to the cutoff prefix and stop
// iterating as soon as we encounter a record newer than the cutoff —
// avoiding a full-bucket scan of potentially hundreds of thousands of
// entries every hour on busy deployments.
func (s *Store) CleanupOldTCPingResults() error {
	cutoffTime := time.Now().Add(-24 * time.Hour)
	cutoffPrefix := []byte(fmt.Sprintf("%d_", cutoffTime.Unix()))
	var keysToDelete [][]byte

	// First pass: collect keys to delete using a cursor with early-exit.
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			// Fast path: if the key's numeric prefix is already >= cutoff
			// prefix, every remaining key is newer too — stop iterating.
			// Compare only the 11-byte "<ts>_" prefix to avoid interpreting
			// the client-id / target suffix. Short keys (legacy / corrupt)
			// fall through to the JSON branch below.
			if len(k) >= len(cutoffPrefix) && bytes.Compare(k[:len(cutoffPrefix)], cutoffPrefix) >= 0 {
				return nil
			}

			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				// Corrupted entry, mark for deletion
				keysToDelete = append(keysToDelete, append([]byte(nil), k...))
				continue
			}

			if result.Timestamp.Before(cutoffTime) {
				keysToDelete = append(keysToDelete, append([]byte(nil), k...))
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	// Second pass: delete old entries
	if len(keysToDelete) > 0 {
		return s.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte(tcpingBucket))
			if bucket == nil {
				return fmt.Errorf("tcping bucket not found")
			}

			for _, key := range keysToDelete {
				if err := bucket.Delete(key); err != nil {
					return err
				}
			}
			return nil
		})
	}

	return nil
}

// TCPingTargetEntry represents a single tcping target with name and address
type TCPingTargetEntry struct {
	Name    string `json:"name"`    // Display name for the target (e.g., "Google DNS")
	Address string `json:"address"` // Target address (e.g., "8.8.8.8:53")
}

// TCPingConfig represents the tcping configuration
type TCPingConfig struct {
	Targets      []TCPingTargetEntry `json:"targets"`       // List of target entries with name and address
	IntervalSecs int                 `json:"interval_secs"` // Polling interval in seconds
}

// GetTCPingConfig retrieves the tcping configuration
func (s *Store) GetTCPingConfig() (*TCPingConfig, error) {
	var config TCPingConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data := bucket.Get([]byte(configKey))
		if data == nil {
			// Return default config if not found: no targets, 60s interval
			config = TCPingConfig{
				Targets:      []TCPingTargetEntry{},
				IntervalSecs: 60,
			}
			return nil
		}

		// Try to unmarshal as new format first
		if err := json.Unmarshal(data, &config); err == nil {
			// Successfully unmarshaled as new format
			return nil
		}

		// Try to unmarshal as old format ([]string) for backward compatibility
		var oldTargets []string
		var oldConfig struct {
			Targets      []string `json:"targets"`
			IntervalSecs int      `json:"interval_secs"`
		}
		if err := json.Unmarshal(data, &oldConfig); err == nil {
			// Convert old format to new format
			config.IntervalSecs = oldConfig.IntervalSecs
			config.Targets = make([]TCPingTargetEntry, len(oldConfig.Targets))
			for i, addr := range oldConfig.Targets {
				config.Targets[i] = TCPingTargetEntry{
					Name:    addr, // Use address as default name
					Address: addr,
				}
			}
			return nil
		}

		// If both fail, try just the targets array
		if err := json.Unmarshal(data, &oldTargets); err == nil {
			// Convert old format to new format
			config.IntervalSecs = 60
			config.Targets = make([]TCPingTargetEntry, len(oldTargets))
			for i, addr := range oldTargets {
				config.Targets[i] = TCPingTargetEntry{
					Name:    addr, // Use address as default name
					Address: addr,
				}
			}
			return nil
		}

		// If all fail, return the original error
		return json.Unmarshal(data, &config)
	})

	if err != nil {
		return nil, err
	}

	if config.Targets == nil {
		config.Targets = []TCPingTargetEntry{}
	}

	return &config, nil
}

// SaveTCPingConfig saves the tcping configuration
func (s *Store) SaveTCPingConfig(config *TCPingConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		return bucket.Put([]byte(configKey), data)
	})
}

// CheckPasswordSet checks if a password has been set
func (s *Store) CheckPasswordSet() (bool, error) {
	var exists bool
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(authBucket))
		if bucket == nil {
			return nil
		}
		exists = bucket.Get([]byte(passwordKey)) != nil
		return nil
	})
	return exists, err
}

// SetPassword sets the admin password (hashed)
func (s *Store) SetPassword(password string) error {
	// Hash password with bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(authBucket))
		if bucket == nil {
			return fmt.Errorf("auth bucket not found")
		}
		return bucket.Put([]byte(passwordKey), hashedPassword)
	})
}

// VerifyPassword verifies the admin password
func (s *Store) VerifyPassword(password string) (bool, error) {
	var hashedPassword []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(authBucket))
		if bucket == nil {
			return fmt.Errorf("auth bucket not found")
		}
		hashedPassword = bucket.Get([]byte(passwordKey))
		if hashedPassword == nil {
			return fmt.Errorf("password not set")
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	return err == nil, nil
}

// GenerateAuthToken generates a random auth token
func GenerateAuthToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// NavbarConfig represents the navbar configuration
//
// HideTags / HideCards intentionally use *negative* (hide_*) names
// so the bool zero-value (`false`) corresponds to the legacy /
// expected behaviour: tags row is shown, card grid is shown.
// This keeps every record already in BoltDB working unchanged
// after upgrade — `json.Unmarshal` leaves the missing fields at
// `false`, so no migration is needed and admins who never open
// the customization modal continue to see the same homepage.
type NavbarConfig struct {
	Text         string `json:"text"`          // Custom text for navbar (default: "Pulse")
	Logo         string `json:"logo"`          // Custom logo URL or SVG (default: built-in SVG)
	SharedSecret string `json:"shared_secret"` // Shared secret for all clients
	CustomCSS    string `json:"custom_css"`    // Custom CSS styles for all pages
	CustomJS     string `json:"custom_js"`     // Custom JavaScript for all pages
	ShowTraffic  bool   `json:"show_traffic"`  // Show real-time and total traffic in detail dropdown
	ShowGlass    bool   `json:"show_glass"`    // Enable glassmorphism (frosted glass) visual effect
	HideTags     bool   `json:"hide_tags"`     // Suppress the tag row in the homepage expand panel
	HideCards    bool   `json:"hide_cards"`    // Suppress the homepage card grid section
}

// GetNavbarConfig retrieves the navbar configuration
func (s *Store) GetNavbarConfig() (*NavbarConfig, error) {
	var config NavbarConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data := bucket.Get([]byte(navbarConfigKey))
		if data == nil {
			// Return default config if not found
			config = NavbarConfig{
				Text:         "Pulse",
				Logo:         "", // Empty means use default SVG
				SharedSecret: "", // Will be generated if needed
			}
			return nil
		}

		return json.Unmarshal(data, &config)
	})

	if err != nil {
		return nil, err
	}

	// Generate shared secret if not set
	if config.SharedSecret == "" {
		// Generate new shared secret
		bytes := make([]byte, 12)
		if _, err := rand.Read(bytes); err == nil {
			config.SharedSecret = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
		} else {
			// Fallback to timestamp-based secret if crypto/rand fails
			config.SharedSecret = fmt.Sprintf("%x", time.Now().UnixNano())[:16]
		}
		// Persist the generated secret. Log failures explicitly: silently
		// swallowing the error used to mask situations where the DB was
		// read-only or full, which then caused every subsequent read to
		// regenerate a fresh secret and break already-registered clients.
		if err := s.SaveNavbarConfig(&config); err != nil {
			log.Printf("⚠️  Failed to persist generated shared secret: %v", err)
		}
	}

	return &config, nil
}

// SaveNavbarConfig saves the navbar configuration
func (s *Store) SaveNavbarConfig(config *NavbarConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		return bucket.Put([]byte(navbarConfigKey), data)
	})
}

// PrivacyConfig represents the privacy configuration
type PrivacyConfig struct {
	Enabled          bool      `json:"enabled"`            // Whether privacy mode is enabled
	ShareToken       string    `json:"share_token"`        // Temporary share token
	TokenExpires     time.Time `json:"token_expires"`      // Token expiration time
	ExpiresInSeconds int       `json:"expires_in_seconds"` // Saved expiration seconds value for UI
}

// GetPrivacyConfig retrieves the privacy configuration
func (s *Store) GetPrivacyConfig() (*PrivacyConfig, error) {
	var config PrivacyConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data := bucket.Get([]byte(privacyConfigKey))
		if data == nil {
			// Return default config if not found
			config = PrivacyConfig{
				Enabled:          false,
				ShareToken:       "",
				TokenExpires:     time.Time{},
				ExpiresInSeconds: 3600, // Default to 1 hour (3600 seconds)
			}
			return nil
		}

		return json.Unmarshal(data, &config)
	})

	if err != nil {
		return nil, err
	}

	return &config, nil
}

// SavePrivacyConfig saves the privacy configuration
func (s *Store) SavePrivacyConfig(config *PrivacyConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		return bucket.Put([]byte(privacyConfigKey), data)
	})
}
