package bugwatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordedServer is a minimal Bugwatch ingestion stub: it records every
// request (path, header, body) and answers the /store/ contract.
type recordedServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
}

type recordedRequest struct {
	Path    string
	Key     string
	Payload *Event // pointer: Event embeds an atomic counter and must not be copied
	Raw     []byte
}

func newRecordedServer(t *testing.T) *recordedServer {
	t.Helper()
	rs := &recordedServer{}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := &Event{}
		body := make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		if err := json.Unmarshal(body, payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rs.mu.Lock()
		rs.requests = append(rs.requests, recordedRequest{
			Path:    r.URL.Path,
			Key:     r.Header.Get("X-Bugwatch-Key"),
			Payload: payload,
			Raw:     body,
		})
		rs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"event_id":"srv-1","issue_id":42}`)
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func (rs *recordedServer) count() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return len(rs.requests)
}

func (rs *recordedServer) last() recordedRequest {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if len(rs.requests) == 0 {
		panic("no request recorded")
	}
	return rs.requests[len(rs.requests)-1]
}

// dsnFor builds a DSN pointing at an httptest server. httptest serves plain
// HTTP, so BUGWATCH_ALLOW_HTTP must be set for these tests.
func dsnFor(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	t.Setenv("BUGWATCH_ALLOW_HTTP", "1")
	return strings.Replace(srv.URL, "://", "://bw_pk_test_key@", 1) + "/api/1"
}

func newTestClient(t *testing.T) (*Client, *recordedServer) {
	t.Helper()
	rs := newRecordedServer(t)
	c, err := NewClient(dsnFor(t, rs.srv))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(c.Close)
	return c, rs
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

// -----------------------------------------------------------------------------
// DSN parsing + Init validation
// -----------------------------------------------------------------------------

func TestParseDSN(t *testing.T) {
	t.Run("valid https with key and path", func(t *testing.T) {
		d, err := parseDSN("https://bw_pk_abc@bugwatch-api.loadmindx.com/api/1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d.publicKey != "bw_pk_abc" || d.host != "bugwatch-api.loadmindx.com" || d.basePath != "/api/1" {
			t.Fatalf("bad parse: %+v", d)
		}
		if got := d.storeURL(); got != "https://bugwatch-api.loadmindx.com/api/1/store/" {
			t.Fatalf("storeURL = %q", got)
		}
	})

	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"empty", "", true},
		{"whitespace only", "   ", true},
		{"https refused without env", "http://k@example.com/api/1", true},
		{"unsupported scheme", "ftp://k@example.com/api/1", true},
		{"missing host", "https://bw_pk_abc", true},
		{"garbage", "://nope", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseDSN(tc.raw)
			if tc.wantErr && err == nil {
				t.Fatalf("parseDSN(%q) = nil error, want error", tc.raw)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("parseDSN(%q) = %v, want nil", tc.raw, err)
			}
		})
	}
}

func TestHTTPAllowedWithEnvVar(t *testing.T) {
	t.Setenv("BUGWATCH_ALLOW_HTTP", "1")
	d, err := parseDSN("http://bw_pk_dev@127.0.0.1:9999/api/1")
	if err != nil {
		t.Fatalf("http:// should be allowed with BUGWATCH_ALLOW_HTTP=1: %v", err)
	}
	if d.storeURL() != "http://127.0.0.1:9999/api/1/store/" {
		t.Fatalf("storeURL = %q", d.storeURL())
	}
}

func TestInitValidAndInvalid(t *testing.T) {
	rs := newRecordedServer(t)

	t.Setenv("BUGWATCH_ALLOW_HTTP", "1")
	valid := strings.Replace(rs.srv.URL, "://", "://bw_pk_test_key@", 1) + "/api/1"

	if err := Init(valid); err != nil {
		t.Fatalf("Init(valid) = %v, want nil", err)
	}
	if Default() == nil {
		t.Fatal("Default() = nil after successful Init")
	}
	Close()
	if Default() != nil {
		t.Fatal("Default() != nil after Close")
	}

	if err := Init(""); err == nil {
		t.Fatal("Init(\"\") = nil error, want error")
	}
	if err := Init("ftp://k@host/x"); err == nil {
		t.Fatal("Init(ftp://...) = nil error, want error")
	}
	if Default() != nil {
		t.Fatal("failed Init must not install a default client")
	}
}

func TestHTTPSEnforcementWithoutEnvVar(t *testing.T) {
	// Ensure the env var is unset even if the outer environment defines it.
	t.Setenv("BUGWATCH_ALLOW_HTTP", "")
	if _, err := NewClient("http://bw_pk_x@example.com/api/1"); err == nil {
		t.Fatal("plain HTTP DSN accepted without BUGWATCH_ALLOW_HTTP=1")
	}
	if err := Init("http://bw_pk_x@example.com/api/1"); err == nil {
		t.Fatal("Init(http://...) accepted without BUGWATCH_ALLOW_HTTP=1")
	}
}

// -----------------------------------------------------------------------------
// Capture exception / message
// -----------------------------------------------------------------------------

func TestCaptureExceptionDelivery(t *testing.T) {
	c, rs := newTestClient(t)

	ev := c.CaptureException(errors.New("boom"))
	if ev == nil {
		t.Fatal("CaptureException returned nil")
	}
	if ev.ID == "" {
		t.Fatal("event ID is empty")
	}
	if !c.Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}

	req := rs.last()
	if req.Path != "/api/1/store/" {
		t.Fatalf("POST path = %q, want /api/1/store/", req.Path)
	}
	if req.Key != "bw_pk_test_key" {
		t.Fatalf("X-Bugwatch-Key = %q", req.Key)
	}
	p := req.Payload
	if p.Level != LevelError {
		t.Fatalf("level = %q, want %q", p.Level, LevelError)
	}
	if p.Platform != "go" {
		t.Fatalf("platform = %q, want go", p.Platform)
	}
	if p.Exception == nil || p.Exception.Value != "boom" {
		t.Fatalf("exception.value = %+v, want \"boom\"", p.Exception)
	}
	if p.Exception.Type == "" {
		t.Fatal("exception.type is empty")
	}
	if p.Timestamp == "" {
		t.Fatal("timestamp is empty")
	}
	if _, err := time.Parse(time.RFC3339, p.Timestamp); err != nil {
		t.Fatalf("timestamp not RFC3339: %v", err)
	}
	if p.Exception.Stacktrace == nil || len(p.Exception.Stacktrace.Frames) == 0 {
		t.Fatal("stacktrace missing or empty")
	}
	innermost := p.Exception.Stacktrace.Frames[0]
	if innermost.Function == "" || innermost.Lineno <= 0 {
		t.Fatalf("bad innermost frame: %+v", innermost)
	}
	if strings.Contains(innermost.Function, sdkModule) || strings.HasPrefix(innermost.Function, "runtime.") {
		t.Fatalf("SDK/runtime frame leaked into stacktrace: %+v", innermost)
	}
	if ev.ServerEventID() != "srv-1" || ev.ServerIssueID() != 42 {
		t.Fatalf("server ids not propagated: id=%q issue=%d", ev.ServerEventID(), ev.ServerIssueID())
	}
}

func TestCaptureExceptionNilError(t *testing.T) {
	c, _ := newTestClient(t)
	if ev := c.CaptureException(nil); ev != nil {
		t.Fatal("CaptureException(nil) must return nil")
	}
}

func TestCaptureMessageAndLevels(t *testing.T) {
	c, rs := newTestClient(t)

	if ev := c.CaptureMessage("hello world", LevelWarning); ev == nil {
		t.Fatal("CaptureMessage returned nil")
	}
	c.CaptureMessage("defaulted level", "bogus-level")
	c.CaptureMessage("", LevelInfo) // empty message must not crash

	if !c.Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	if rs.count() != 3 {
		t.Fatalf("server received %d events, want 3", rs.count())
	}
	first := rs.requests[0].Payload
	if first.Message != "hello world" || first.Level != LevelWarning {
		t.Fatalf("first event = {level:%q msg:%q}", first.Level, first.Message)
	}
	second := rs.requests[1].Payload
	if second.Level != LevelError {
		t.Fatalf("unknown level normalized to %q, want %q", second.Level, LevelError)
	}
	third := rs.requests[2].Payload
	if third.Message != "" {
		t.Fatalf("empty message became %q", third.Message)
	}
}

// -----------------------------------------------------------------------------
// Context: breadcrumbs, user, tags, redaction
// -----------------------------------------------------------------------------

func TestBreadcrumbsAttached(t *testing.T) {
	c, rs := newTestClient(t)

	c.AddBreadcrumb("db", "query users")
	c.AddBreadcrumb("http", "GET /health")
	c.CaptureMessage("with trail", LevelInfo)

	if !c.Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	bcs := rs.last().Payload.Breadcrumbs
	if len(bcs) != 2 {
		t.Fatalf("got %d breadcrumbs, want 2", len(bcs))
	}
	if bcs[0].Category != "db" || bcs[0].Message != "query users" {
		t.Fatalf("breadcrumb[0] = %+v", bcs[0])
	}
	if bcs[1].Category != "http" || bcs[1].Message != "GET /health" {
		t.Fatalf("breadcrumb[1] = %+v", bcs[1])
	}
	for _, bc := range bcs {
		if _, err := time.Parse(time.RFC3339, bc.Timestamp); err != nil {
			t.Fatalf("breadcrumb timestamp not RFC3339: %v", err)
		}
	}
}

func TestBreadcrumbTrailIsCapped(t *testing.T) {
	c, _ := newTestClient(t)
	for i := 0; i < maxBreadcrumbs+50; i++ {
		c.AddBreadcrumb("cat", fmt.Sprintf("m%d", i))
	}
	c.mu.RLock()
	n := len(c.breadcrumbs)
	lastMsg := c.breadcrumbs[n-1].Message
	c.mu.RUnlock()
	if n != maxBreadcrumbs {
		t.Fatalf("trail length = %d, want %d", n, maxBreadcrumbs)
	}
	if lastMsg != fmt.Sprintf("m%d", maxBreadcrumbs+49) {
		t.Fatalf("oldest entries were not dropped; last = %q", lastMsg)
	}
}

func TestUserAndTagsAttached(t *testing.T) {
	c, rs := newTestClient(t)

	c.SetUser("42", "jane@example.com")
	c.SetTag("env", "prod")
	c.CaptureMessage("contextualized", LevelError)

	if !c.Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	p := rs.last().Payload
	if p.User == nil || p.User.ID != "42" || p.User.Email != "jane@example.com" {
		t.Fatalf("user = %+v", p.User)
	}
	if p.Tags["env"] != "prod" {
		t.Fatalf("tags = %+v", p.Tags)
	}
	if p.Environment != "production" {
		t.Fatalf("environment = %q, want production", p.Environment)
	}
}

func TestSensitiveRedaction(t *testing.T) {
	c, rs := newTestClient(t)

	c.SetUser("42", "secret@corp.io")
	c.SetTag("user.email", "sensitive")
	c.CaptureMessage("redacted email", LevelError)

	if !c.Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	u := rs.last().Payload.User
	if u.Email != RedactedPlaceholder {
		t.Fatalf("sensitive email leaked: %q", u.Email)
	}
	if u.ID != "42" {
		t.Fatalf("non-sensitive id was altered: %q", u.ID)
	}
}

func TestSensitiveRedactionPasswordAndID(t *testing.T) {
	c, rs := newTestClient(t)

	c.SetUser("root", "root@corp.io")
	c.tags["password"] = "sensitive" // direct write to also cover the password field
	c.tags["id"] = "sensitive"
	c.user.Password = "hunter2"
	c.CaptureMessage("all redacted", LevelError)

	if !c.Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	u := rs.last().Payload.User
	if u.Password != RedactedPlaceholder {
		t.Fatalf("sensitive password leaked: %q", u.Password)
	}
	if u.ID != RedactedPlaceholder {
		t.Fatalf("sensitive id leaked: %q", u.ID)
	}
}

// -----------------------------------------------------------------------------
// Flush semantics
// -----------------------------------------------------------------------------

func TestFlushDrainsQueue(t *testing.T) {
	c, rs := newTestClient(t)

	const n = 100
	for i := 0; i < n; i++ {
		if c.CaptureMessage(fmt.Sprintf("evt-%d", i), LevelInfo) == nil {
			t.Fatalf("capture %d dropped unexpectedly", i)
		}
	}
	if !c.Flush(10 * time.Second) {
		t.Fatal("Flush returned false")
	}
	waitUntil(t, 2*time.Second, func() bool { return rs.count() == n },
		fmt.Sprintf("server received %d/%d events after Flush", rs.count(), n))
}

func TestFlushTimeoutOnStuckServer(t *testing.T) {
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-gate // block until the test releases us
		w.WriteHeader(http.StatusOK)
	}))
	// Order matters: srv.Close() waits for outstanding handlers, so the gate
	// must be released first (defers run LIFO).
	defer srv.Close()
	defer close(gate)

	c, err := NewClient(dsnFor(t, srv))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(c.Close)

	// Enqueue one event: the worker is now stuck inside send() on the gated
	// server, so the flush barrier queued behind it cannot be reached.
	if c.CaptureMessage("stuck", LevelError) == nil {
		t.Fatal("capture dropped unexpectedly")
	}

	start := time.Now()
	if ok := c.Flush(150 * time.Millisecond); ok {
		t.Fatal("Flush reported success while the server was stuck")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Flush blocked for %v, want ~timeout", elapsed)
	}
}

func TestFlushWithoutClient(t *testing.T) {
	globalMu.Lock()
	saved := global
	global = nil
	globalMu.Unlock()
	defer func() {
		globalMu.Lock()
		global = saved
		globalMu.Unlock()
	}()
	if !Flush(time.Second) {
		t.Fatal("package-level Flush without client must return true")
	}
}

// -----------------------------------------------------------------------------
// Non-blocking guarantees
// -----------------------------------------------------------------------------

func TestCaptureNeverBlocksWhenQueueFull(t *testing.T) {
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-gate
		w.WriteHeader(http.StatusOK)
	}))
	// Order matters: srv.Close() waits for outstanding handlers, so the gate
	// must be released first (defers run LIFO).
	defer srv.Close()
	defer close(gate)

	c, err := NewClient(dsnFor(t, srv))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(c.Close)

	start := time.Now()
	dropped := 0
	for i := 0; i < defaultQueueSize+200; i++ {
		if c.CaptureMessage("flood", LevelInfo) == nil {
			dropped++
		}
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("capturing %d events took %v — capture blocked", defaultQueueSize+200, elapsed)
	}
	if dropped == 0 {
		t.Fatal("expected drops once the queue is full")
	}
}

func TestCaptureOnUninitialisedPackageAPI(t *testing.T) {
	globalMu.Lock()
	saved := global
	global = nil
	globalMu.Unlock()
	defer func() {
		globalMu.Lock()
		global = saved
		globalMu.Unlock()
	}()

	if CaptureException(errors.New("x")) != nil {
		t.Fatal("CaptureException without client must return nil")
	}
	if CaptureMessage("x", LevelError) != nil {
		t.Fatal("CaptureMessage without client must return nil")
	}
	AddBreadcrumb("c", "m") // must not panic
	SetUser("u", "e")       // must not panic
	SetTag("k", "v")        // must not panic
}

// -----------------------------------------------------------------------------
// Package-level API end-to-end
// -----------------------------------------------------------------------------

func TestPackageLevelEndToEnd(t *testing.T) {
	rs := newRecordedServer(t)
	dsn := dsnFor(t, rs.srv)

	if err := Init(dsn); err != nil {
		t.Fatalf("Init: %v", err)
	}
	SetUser("7", "bob@example.com")
	SetTag("service", "api")
	AddBreadcrumb("auth", "login ok")

	ev := CaptureException(errors.New("prod incident"))
	if ev == nil {
		t.Fatal("CaptureException returned nil")
	}
	if !Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	Close()

	req := rs.last()
	if req.Key != "bw_pk_test_key" {
		t.Fatalf("key = %q", req.Key)
	}
	p := req.Payload
	if p.User == nil || p.User.ID != "7" {
		t.Fatalf("user = %+v", p.User)
	}
	if p.Tags["service"] != "api" {
		t.Fatalf("tags = %+v", p.Tags)
	}
	if len(p.Breadcrumbs) != 1 || p.Breadcrumbs[0].Category != "auth" {
		t.Fatalf("breadcrumbs = %+v", p.Breadcrumbs)
	}
	if p.Exception == nil || p.Exception.Value != "prod incident" {
		t.Fatalf("exception = %+v", p.Exception)
	}
}

func TestSetDefaultClosesPreviousClient(t *testing.T) {
	rs := newRecordedServer(t)
	c1, err := NewClient(dsnFor(t, rs.srv))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	SetDefault(c1)
	c2, err := NewClient(dsnFor(t, rs.srv))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	SetDefault(c2)
	if Default() != c2 {
		t.Fatal("Default() does not point at the newest client")
	}
	// c1 must be closed: its done channel is shut.
	select {
	case <-c1.done:
	default:
		t.Fatal("previous default client was not closed")
	}
	SetDefault(nil)
	Close()
}

func TestNewEventIDShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newEventID()
		if seen[id] {
			t.Fatalf("duplicate event id %q", id)
		}
		seen[id] = true
		if len(id) != 36 || strings.Count(id, "-") != 4 {
			t.Fatalf("malformed uuid v4: %q", id)
		}
		if id[14] != '4' {
			t.Fatalf("version nibble not 4: %q", id)
		}
	}
}
