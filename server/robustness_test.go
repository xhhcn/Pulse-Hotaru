package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- geo resolution never blocks ---------------------------------------------

func TestResolveLocationReportedValueWins(t *testing.T) {
	cache := NewIPCountryCache()
	got := resolveLocation(cache, nil, "Los Angeles, US", "8.8.8.8", "")
	if got != "US" {
		t.Fatalf("resolveLocation() = %q, want US", got)
	}
}

func TestResolveLocationReusesStoredLocationWhenIPUnchanged(t *testing.T) {
	cache := NewIPCountryCache()
	existing := &SystemMetric{ID: "sys", Location: "DE", IPv4: "203.0.113.10"}
	got := resolveLocation(cache, existing, "", "203.0.113.10", "")
	if got != "DE" {
		t.Fatalf("resolveLocation() = %q, want DE (persisted value reused)", got)
	}
	if _, found := cache.Get("203.0.113.10"); found {
		t.Fatalf("cache must not be touched on the persisted-value path")
	}
}

func TestResolveLocationUsesCacheAndFallsBackAcrossFamilies(t *testing.T) {
	cache := NewIPCountryCache()
	cache.SetFailed("203.0.113.10")
	cache.Set("2001:db8::1", "JP")
	got := resolveLocation(cache, nil, "", "203.0.113.10", "2001:db8::1")
	if got != "JP" {
		t.Fatalf("resolveLocation() = %q, want JP (v4 cached failure, v6 cache hit)", got)
	}
}

func TestResolveLocationKeepsOldLocationWhileIPChanges(t *testing.T) {
	cache := NewIPCountryCache()
	// Old IP resolved earlier; new IP has a cached answer, so the change is
	// picked up immediately without any network call.
	cache.Set("198.51.100.7", "FR")
	existing := &SystemMetric{ID: "sys", Location: "DE", IPv4: "203.0.113.10"}
	got := resolveLocation(cache, existing, "", "198.51.100.7", "")
	if got != "FR" {
		t.Fatalf("resolveLocation() = %q, want FR", got)
	}
}

func TestResolveLocationSkipsPrivateAddresses(t *testing.T) {
	cache := NewIPCountryCache()
	start := time.Now()
	got := resolveLocation(cache, nil, "", "192.168.1.5", "fd00::1")
	if got != "" {
		t.Fatalf("resolveLocation() = %q, want empty for private IPs", got)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("resolveLocation blocked for %v", time.Since(start))
	}
}

// --- tcping batches are idempotent --------------------------------------------

func TestSaveClientPushBatchIgnoresResentMeasurements(t *testing.T) {
	store := newTestStore(t)
	measured := time.Now().UTC().Add(-2 * time.Minute)
	lat := 12.5
	batch := []TCPingResult{{ClientID: "agent", Target: "1.1.1.1:443", Latency: &lat, Timestamp: measured, ExactTimestamp: true}}
	metric := SystemMetric{ID: "agent", Name: "agent"}

	// First push commits; the agent times out waiting and re-sends the same
	// measurement on its next push.
	for i := 0; i < 2; i++ {
		if err := store.SaveClientPushBatch(metric, batch); err != nil {
			t.Fatalf("SaveClientPushBatch(%d) error = %v", i, err)
		}
	}
	results, err := store.GetTCPingResults("agent", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("GetTCPingResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1 (duplicate must be dropped)", len(results))
	}
}

// --- SSE subscriber caps --------------------------------------------------------

func TestSSEBrokerEnforcesPerIPCap(t *testing.T) {
	b := NewSSEBroker()
	subs := make([]*sseSubscriber, 0, b.maxPerIP)
	for i := 0; i < b.maxPerIP; i++ {
		s, err := b.Subscribe(SSEViewPublic, "10.0.0.1")
		if err != nil {
			t.Fatalf("Subscribe(%d) error = %v", i, err)
		}
		subs = append(subs, s)
	}
	if _, err := b.Subscribe(SSEViewPublic, "10.0.0.1"); err == nil {
		t.Fatalf("Subscribe beyond per-IP cap must fail")
	}
	if _, err := b.Subscribe(SSEViewPublic, "10.0.0.2"); err != nil {
		t.Fatalf("other IP must still be admitted: %v", err)
	}
	b.Unsubscribe(subs[0])
	if _, err := b.Subscribe(SSEViewPublic, "10.0.0.1"); err != nil {
		t.Fatalf("Unsubscribe must free a per-IP slot: %v", err)
	}
	if got := b.SubscriberCount(); got != b.maxPerIP+1 {
		t.Fatalf("SubscriberCount() = %d, want %d", got, b.maxPerIP+1)
	}
	// Admin streams are never refused by the anonymous caps.
	for i := 0; i < 3; i++ {
		if _, err := b.Subscribe(SSEViewAdmin, "10.0.0.1"); err != nil {
			t.Fatalf("admin Subscribe must bypass the per-IP cap: %v", err)
		}
	}
}

// --- admin visibility toggles survive agent writes ----------------------------

func adminRequest(t *testing.T, method, path string, body interface{}) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-admin-token")
	return req
}

func TestVisibilityTogglesPersistThroughPushAndAdminEdit(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()

	authTokensMu.Lock()
	authTokens["test-admin-token"] = time.Now().Add(time.Hour)
	authTokensMu.Unlock()
	t.Cleanup(func() {
		authTokensMu.Lock()
		delete(authTokens, "test-admin-token")
		authTokensMu.Unlock()
	})

	// Admin creates the system.
	rr := httptest.NewRecorder()
	handleIngestMetric(store, nil, rr, adminRequest(t, http.MethodPost, "/api/metrics", map[string]interface{}{"id": "vm1", "name": "VM 1"}))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("create: status %d body %s", rr.Code, rr.Body.String())
	}
	created, _ := store.Get("vm1")
	if created == nil || created.HideOnHome || created.HideTCPing {
		t.Fatalf("new systems must default to shown: %+v", created)
	}

	// Admin edit flips both toggles.
	hide := true
	rr = httptest.NewRecorder()
	handleIngestMetric(store, nil, rr, adminRequest(t, http.MethodPost, "/api/metrics", map[string]interface{}{
		"id": "vm1", "name": "VM 1 renamed", "tags": []string{"a"}, "hide_on_home": hide, "hide_tcping": hide,
	}))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("edit: status %d body %s", rr.Code, rr.Body.String())
	}
	edited, _ := store.Get("vm1")
	if !edited.HideOnHome || !edited.HideTCPing || edited.Name != "VM 1 renamed" {
		t.Fatalf("edit did not persist toggles: %+v", edited)
	}

	// Agent push (with the secret) must not reset them, even if it sends
	// explicit false values.
	pushBody := map[string]interface{}{
		"id": "vm1", "name": "agent-name", "uptime": 123, "os": "Linux", "cpu": 3.0,
		"secret": edited.Secret, "location": "US", "hide_on_home": false, "hide_tcping": false,
	}
	data, _ := json.Marshal(pushBody)
	req := httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: status %d body %s", rr.Code, rr.Body.String())
	}
	pushed, _ := store.Get("vm1")
	if !pushed.HideOnHome || !pushed.HideTCPing {
		t.Fatalf("agent push reset the toggles: %+v", pushed)
	}
	if pushed.Name != "VM 1 renamed" || pushed.CPU != 3.0 || pushed.Location != "US" {
		t.Fatalf("push did not update metrics as expected: %+v", pushed)
	}

	// Admin edit without the toggle fields (older UI) leaves them untouched.
	rr = httptest.NewRecorder()
	handleIngestMetric(store, nil, rr, adminRequest(t, http.MethodPost, "/api/metrics", map[string]interface{}{"id": "vm1", "name": "VM 1 again"}))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("edit2: status %d body %s", rr.Code, rr.Body.String())
	}
	again, _ := store.Get("vm1")
	if !again.HideOnHome || !again.HideTCPing {
		t.Fatalf("edit without toggle fields must preserve them: %+v", again)
	}

	// Public and admin snapshots both still contain the hidden system (the
	// homepage filters client-side; the API keeps returning it).
	for _, admin := range []bool{true, false} {
		snap, err := buildMetricsSnapshot(store, registry, admin)
		if err != nil {
			t.Fatalf("buildMetricsSnapshot(%v) error = %v", admin, err)
		}
		if len(snap) != 1 || !snap[0].HideOnHome {
			t.Fatalf("snapshot(admin=%v) = %+v, want the hidden system with hide_on_home=true", admin, snap)
		}
	}
}

// --- old tcping samples keep their real timestamps --------------------------------

func TestClientPushKeepsBackfilledTimestampsAndDropsExpired(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "vm2", Name: "VM 2"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	now := time.Now().UTC()
	old := now.Add(-40 * time.Minute) // server was down for a while: must be kept verbatim
	expired := now.Add(-25 * time.Hour)
	body := map[string]interface{}{
		"id": "vm2", "name": "x", "uptime": 5, "location": "US",
		"tcping_results": []map[string]interface{}{
			{"target": "1.1.1.1:443", "latency": 10, "success": true, "measured_at": old.Format(time.RFC3339Nano)},
			{"target": "1.1.1.1:443", "latency": 11, "success": true, "measured_at": expired.Format(time.RFC3339Nano)},
			{"target": "1.1.1.1:443", "latency": 12, "success": true, "measured_at": now.Format(time.RFC3339Nano)},
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: status %d body %s", rr.Code, rr.Body.String())
	}
	results, err := store.GetTCPingResults("vm2", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("GetTCPingResults: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2 (expired sample dropped)", len(results))
	}
	if d := results[0].Timestamp.Sub(old); d < -time.Second || d > time.Second {
		t.Fatalf("backfilled sample re-stamped: got %v want %v", results[0].Timestamp, old)
	}
	m, _ := store.Get("vm2")
	if got := m.TCPingData["1.1.1.1:443"]; got.Latency != 12 {
		t.Fatalf("latest tcping datum = %+v, want the newest sample (12 ms)", got)
	}
}

// --- legacy agents (no measured_at) keep every sample in a batch ---------------

func TestClientPushKeepsAllSamplesFromLegacyAgents(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "legacy", Name: "Legacy"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	body := map[string]interface{}{
		"id": "legacy", "name": "x", "uptime": 5, "location": "US",
		"tcping_results": []map[string]interface{}{
			{"target": "1.1.1.1:443", "latency": 10, "success": true},
			{"target": "1.1.1.1:443", "latency": 11, "success": true},
			{"target": "1.1.1.1:443", "latency": 12, "success": false},
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: status %d body %s", rr.Code, rr.Body.String())
	}
	results, err := store.GetTCPingResults("legacy", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("GetTCPingResults: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3 (server-stamped samples must never be deduplicated)", len(results))
	}
}

func TestClientPushShiftsSkewedAgentClock(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "skew", Name: "Skew"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	now := time.Now().UTC()
	// Agent clock is 6 h behind: its "just measured" sample says now-6h and
	// its 1-minute-old sample says now-6h-1m. Both must land near now.
	body := map[string]interface{}{
		"id": "skew", "name": "x", "uptime": 5, "location": "US",
		"tcping_results": []map[string]interface{}{
			{"target": "1.1.1.1:443", "latency": 10, "success": true, "measured_at": now.Add(-6 * time.Hour).Format(time.RFC3339Nano)},
			{"target": "1.1.1.1:443", "latency": 11, "success": true, "measured_at": now.Add(-6*time.Hour - time.Minute).Format(time.RFC3339Nano)},
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: status %d body %s", rr.Code, rr.Body.String())
	}
	results, err := store.GetTCPingResults("skew", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("GetTCPingResults: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for _, r := range results {
		if age := time.Since(r.Timestamp); age > 2*time.Minute || age < -5*time.Second {
			t.Fatalf("skewed sample not shifted to the present: %v (age %v)", r.Timestamp, age)
		}
	}
	m, _ := store.Get("skew")
	if got := m.TCPingData["1.1.1.1:443"]; got.Latency != 10 {
		t.Fatalf("latest datum = %+v, want the newest sample (10 ms)", got)
	}
}

// --- admin edits survive a concurrent agent write ------------------------------

func TestAgentWriteNeverRevertsConcurrentAdminEdit(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "race", Name: "Old name", Secret: "s", Order: 1}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Agent reads its snapshot ...
	snapshot, _ := store.Get("race")
	agentRecord := *snapshot
	agentRecord.CPU = 55

	// ... the admin edits in between ...
	edited := *snapshot
	edited.Name = "New name"
	edited.Tags = []string{"prod"}
	edited.Order = 7
	edited.HideOnHome = true
	edited.HideTCPing = true
	if err := store.Upsert(edited); err != nil {
		t.Fatalf("admin Upsert: %v", err)
	}

	// ... and the agent's write lands last, on both agent paths.
	if err := store.UpsertFromAgent(agentRecord); err != nil {
		t.Fatalf("UpsertFromAgent: %v", err)
	}
	got, _ := store.Get("race")
	if got.CPU != 55 {
		t.Fatalf("agent metrics not written: %+v", got)
	}
	if got.Name != "New name" || len(got.Tags) != 1 || got.Order != 7 || !got.HideOnHome || !got.HideTCPing || got.Secret != "s" {
		t.Fatalf("UpsertFromAgent reverted admin-owned fields: %+v", got)
	}

	agentRecord.CPU = 66
	if err := store.SaveClientPushBatch(agentRecord, nil); err != nil {
		t.Fatalf("SaveClientPushBatch: %v", err)
	}
	got, _ = store.Get("race")
	if got.CPU != 66 || got.Name != "New name" || !got.HideOnHome || !got.HideTCPing || got.Order != 7 {
		t.Fatalf("SaveClientPushBatch reverted admin-owned fields: %+v", got)
	}
}

// --- admin operations: single-transaction reorder, key-based history deletes ----

func TestUpdateOrdersTouchesOnlyOrder(t *testing.T) {
	store := newTestStore(t)
	for i, id := range []string{"a", "b", "c"} {
		if err := store.Upsert(SystemMetric{ID: id, Name: "n-" + id, Order: i, CPU: float64(10 * i), Secret: "s"}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	if err := store.UpdateOrders([]string{"c", "missing", "a", "b"}); err != nil {
		t.Fatalf("UpdateOrders: %v", err)
	}
	want := map[string]int{"c": 0, "a": 2, "b": 3}
	for id, order := range want {
		m, _ := store.Get(id)
		if m.Order != order {
			t.Fatalf("%s: order = %d, want %d", id, m.Order, order)
		}
		if m.Secret != "s" || m.Name != "n-"+id {
			t.Fatalf("%s: other fields changed: %+v", id, m)
		}
	}
}

func TestDeleteTCPingHistoryDoesNotMatchPrefixCollisions(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	lat := 1.0
	put := func(client, target string, offset time.Duration) {
		if err := store.SaveTCPingResult(TCPingResult{ClientID: client, Target: target, Latency: &lat, Timestamp: now.Add(offset)}); err != nil {
			t.Fatalf("SaveTCPingResult: %v", err)
		}
	}
	put("a", "x:1", -time.Minute)
	put("a_b", "x:1", -2*time.Minute) // shares the "a_" key prefix
	put("a", "x:10", -3*time.Minute)  // shares the "_x:1" suffix start
	put("b", "x:1", -4*time.Minute)

	if err := store.DeleteTCPingResultsByClient("a"); err != nil {
		t.Fatalf("DeleteTCPingResultsByClient: %v", err)
	}
	if r, _ := store.GetTCPingResults("a"); len(r) != 0 {
		t.Fatalf("client a still has %d records", len(r))
	}
	if r, _ := store.GetTCPingResults("a_b"); len(r) != 1 {
		t.Fatalf("client a_b lost records: %d", len(r))
	}
	if err := store.DeleteTCPingResultsByTarget("x:1"); err != nil {
		t.Fatalf("DeleteTCPingResultsByTarget: %v", err)
	}
	if r, _ := store.GetTCPingResults("b", "x:1"); len(r) != 0 {
		t.Fatalf("target x:1 of b still present")
	}
	if r, _ := store.GetTCPingResults("a_b"); len(r) != 0 {
		t.Fatalf("target x:1 of a_b still present")
	}
}

func TestDeleteTCPingKeysChunksLargeSets(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	lat := 1.0
	var batch []TCPingResult
	for i := 0; i < 2*tcpingDeleteChunk+7; i++ {
		batch = append(batch, TCPingResult{ClientID: "big", Target: "t:1", Latency: &lat, Timestamp: now.Add(-time.Duration(i) * time.Second), ExactTimestamp: true})
	}
	if err := store.SaveClientPushBatch(SystemMetric{ID: "big", Name: "big"}, batch); err != nil {
		t.Fatalf("SaveClientPushBatch: %v", err)
	}
	if err := store.DeleteTCPingResultsByClient("big"); err != nil {
		t.Fatalf("DeleteTCPingResultsByClient: %v", err)
	}
	if r, _ := store.GetTCPingResults("big"); len(r) != 0 {
		t.Fatalf("%d records survived the chunked delete", len(r))
	}
}

// --- privacy: a plain save keeps the existing link, its expiry and its duration ---

func TestPrivacySaveWithoutNewTokenKeepsExpiryAndDuration(t *testing.T) {
	store := newTestStore(t)
	authTokensMu.Lock()
	authTokens["test-admin-token"] = time.Now().Add(time.Hour)
	authTokensMu.Unlock()
	t.Cleanup(func() {
		authTokensMu.Lock()
		delete(authTokens, "test-admin-token")
		authTokensMu.Unlock()
	})

	// Generate a 24 h link.
	rr := httptest.NewRecorder()
	handleSetPrivacyConfig(store, rr, adminRequest(t, http.MethodPost, "/api/privacy/config", map[string]interface{}{
		"enabled": true, "share_token": "tok-1", "expires_in_seconds": 86400,
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("generate: status %d body %s", rr.Code, rr.Body.String())
	}
	first, _ := store.GetPrivacyConfig()
	if first.ShareToken != "tok-1" || first.ExpiresInSeconds != 86400 || first.TokenExpires.IsZero() {
		t.Fatalf("unexpected stored config after generate: %+v", first)
	}

	// Plain save (toggle only) as the fixed admin UI sends it.
	time.Sleep(1100 * time.Millisecond)
	rr = httptest.NewRecorder()
	handleSetPrivacyConfig(store, rr, adminRequest(t, http.MethodPost, "/api/privacy/config", map[string]interface{}{
		"enabled": false, "share_token": "tok-1", "expires_in_seconds": 0, "token_expires": first.TokenExpires.Format(time.RFC3339),
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("plain save: status %d body %s", rr.Code, rr.Body.String())
	}
	second, _ := store.GetPrivacyConfig()
	if second.Enabled || second.ShareToken != "tok-1" {
		t.Fatalf("plain save changed token/enabled: %+v", second)
	}
	if d := second.TokenExpires.Sub(first.TokenExpires); d < -time.Second || d > time.Second {
		t.Fatalf("plain save restarted the countdown: %v vs %v", second.TokenExpires, first.TokenExpires)
	}
	if second.ExpiresInSeconds != 86400 {
		t.Fatalf("plain save lost the saved duration: %d", second.ExpiresInSeconds)
	}

	// Empty share_token is still an explicit revoke.
	rr = httptest.NewRecorder()
	handleSetPrivacyConfig(store, rr, adminRequest(t, http.MethodPost, "/api/privacy/config", map[string]interface{}{"enabled": true, "share_token": ""}))
	third, _ := store.GetPrivacyConfig()
	if third.ShareToken != "" || !third.TokenExpires.IsZero() {
		t.Fatalf("revoke did not clear the link: %+v", third)
	}
}

// --- server-driven tcping reaches pull-mode agents ----------------------------

func TestTCPingPullGateDistinguishesOwnPollFromPush(t *testing.T) {
	now := time.Now()
	fresh := &SystemMetric{ID: "a", UpdatedAt: now.Add(-2 * time.Second)}

	// Pure pull-mode agent: our poll wrote the record moments ago.
	pulled := ClientInfo{ID: "a", LastPollAt: now.Add(-2 * time.Second)}
	if tcpingPullSuppressed(pulled, fresh, now) {
		t.Fatalf("a record written by our own poll must not suppress the tcping pull")
	}
	// Never polled, yet the record is fresh: a push wrote it (re-registration window).
	if !tcpingPullSuppressed(ClientInfo{ID: "a"}, fresh, now) {
		t.Fatalf("a fresh record we did not poll must suppress the pull")
	}
	// Poll happened, but a newer write landed afterwards: something else is pushing.
	stalePoll := ClientInfo{ID: "a", LastPollAt: now.Add(-8 * time.Second)}
	if !tcpingPullSuppressed(stalePoll, fresh, now) {
		t.Fatalf("a write newer than our last poll must suppress the pull")
	}
	// Old record: never suppressed.
	old := &SystemMetric{ID: "a", UpdatedAt: now.Add(-30 * time.Second)}
	if tcpingPullSuppressed(ClientInfo{ID: "a"}, old, now) {
		t.Fatalf("a stale record must not suppress the pull")
	}
}

// --- connect-time snapshot reuse must never serve stale data -----------------

func TestSSEBrokerLatestSnapshotAgeAndPerView(t *testing.T) {
	b := NewSSEBroker()
	if _, ok := b.LatestSnapshot(SSEViewPublic); ok {
		t.Fatalf("empty broker must not return a snapshot")
	}
	b.RememberSnapshot(SSEViewAdmin, "admin-1")
	if _, ok := b.LatestSnapshot(SSEViewPublic); ok {
		t.Fatalf("a payload remembered for the admin view must not be served to the public view")
	}
	if p, ok := b.LatestSnapshot(SSEViewAdmin); !ok || p != "admin-1" {
		t.Fatalf("fresh admin payload not returned: %q %v", p, ok)
	}
	b.BroadcastByView(map[SSEView]string{SSEViewPublic: "pub-2", SSEViewAdmin: "admin-2"})
	if p, _ := b.LatestSnapshot(SSEViewPublic); p != "pub-2" {
		t.Fatalf("broadcast payload not remembered: %q", p)
	}
	b.mu.Lock()
	for v := range b.latestAt {
		b.latestAt[v] = time.Now().Add(-2 * sseSnapshotMaxAge)
	}
	b.mu.Unlock()
	if _, ok := b.LatestSnapshot(SSEViewPublic); ok {
		t.Fatalf("a payload older than %v must not prime a new subscriber", sseSnapshotMaxAge)
	}
}
