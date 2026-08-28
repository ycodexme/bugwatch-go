// Package bugwatch provides the official Go SDK for Bugwatch, an error
// tracking platform.
//
// The SDK is intentionally dependency-free (standard library only) and
// non-blocking: events are pushed onto an internal queue and delivered by a
// single background worker, so a slow or unreachable Bugwatch server never
// stalls the host application. Call Flush before process exit to make sure
// queued events are delivered.
//
// Basic usage:
//
//	if err := bugwatch.Init("https://bw-your_key@bugwatch-api.loadmindx.com/api/1"); err != nil {
//		log.Fatal(err)
//	}
//	defer bugwatch.Flush(5 * time.Second)
//
//	bugwatch.SetUser("42", "jane@example.com")
//	bugwatch.AddBreadcrumb("db", "query users")
//	if err := doWork(); err != nil {
//		bugwatch.CaptureException(err)
//	}
package bugwatch

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event severity levels accepted by the Bugwatch ingestion API.
const (
	LevelDebug   = "debug"
	LevelInfo    = "info"
	LevelWarning = "warning"
	LevelError   = "error"
	LevelFatal   = "fatal"
)

const (
	// RedactedPlaceholder replaces any user field tagged "sensitive".
	RedactedPlaceholder = "[redacted]"

	sdkModule          = "github.com/ycodexme/bugwatch-go"
	defaultQueueSize   = 2048
	maxBreadcrumbs     = 100
	defaultHTTPTimeout = 10 * time.Second
	maxSourceLineLen   = 512
)

// allowHTTP reports whether plain HTTP DSNs are permitted. This exists for
// local development and tests only; production DSNs must use HTTPS.
func allowHTTP() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("BUGWATCH_ALLOW_HTTP")))
	return v == "1" || v == "true"
}

// -----------------------------------------------------------------------------
// Data model (matches the Bugwatch /store/ ingestion payload)
// -----------------------------------------------------------------------------

// Frame is a single stacktrace frame.
type Frame struct {
	Filename    string `json:"filename"`
	Function    string `json:"function"`
	Lineno      int    `json:"lineno"`
	Colno       int    `json:"colno,omitempty"`
	ContextLine string `json:"context_line,omitempty"`
	InApp       bool   `json:"in_app,omitempty"`
}

// Stacktrace is a list of frames, innermost (crash site) first.
type Stacktrace struct {
	Frames []Frame `json:"frames"`
}

// Exception describes a captured error.
type Exception struct {
	Type       string      `json:"type"`
	Value      string      `json:"value"`
	Stacktrace *Stacktrace `json:"stacktrace,omitempty"`
}

// Breadcrumb is a timestamped trail entry attached to events.
type Breadcrumb struct {
	Category  string `json:"category"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"` // RFC3339
}

// User is the user context attached to events.
type User struct {
	ID       string `json:"id,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

// RequestInfo describes the HTTP request being served when the event fired.
type RequestInfo struct {
	URL    string `json:"url,omitempty"`
	Method string `json:"method,omitempty"`
}

// Event is the payload POSTed to <dsn>/store/.
type Event struct {
	ID          string            `json:"event_id"`
	Level       string            `json:"level"`
	Message     string            `json:"message,omitempty"`
	Exception   *Exception        `json:"exception,omitempty"`
	Timestamp   string            `json:"timestamp"` // RFC3339
	Environment string            `json:"environment,omitempty"`
	Release     string            `json:"release,omitempty"`
	Platform    string            `json:"platform"`
	Breadcrumbs []Breadcrumb      `json:"breadcrumbs,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	User        *User             `json:"user,omitempty"`
	Request     *RequestInfo      `json:"request,omitempty"`

	serverEventID string
	serverIssueID atomic.Int64
}

// ServerEventID returns the event_id assigned by the server after delivery,
// or "" if the event has not been delivered yet.
func (e *Event) ServerEventID() string { return e.serverEventID }

// ServerIssueID returns the issue_id assigned by the server after delivery,
// or 0 if the event has not been delivered yet.
func (e *Event) ServerIssueID() int64 { return e.serverIssueID.Load() }

// applyRedaction enforces the privacy rule: any user field whose tag value is
// "sensitive" never leaves the process in clear text.
func (e *Event) applyRedaction() {
	if e.User == nil || len(e.Tags) == 0 {
		return
	}
	sensitive := func(keys ...string) bool {
		for _, k := range keys {
			if strings.EqualFold(strings.TrimSpace(e.Tags[k]), "sensitive") {
				return true
			}
		}
		return false
	}
	if sensitive("user.email", "email") {
		e.User.Email = RedactedPlaceholder
	}
	if sensitive("user.password", "password") {
		e.User.Password = RedactedPlaceholder
	}
	if sensitive("user.id", "id") {
		e.User.ID = RedactedPlaceholder
	}
}

func normalizeLevel(level string) string {
	switch level {
	case LevelDebug, LevelInfo, LevelWarning, LevelError, LevelFatal:
		return level
	default:
		return LevelError
	}
}

// newEventID returns a random UUID-v4-shaped identifier built from
// crypto/rand.
func newEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is catastrophic and extremely rare; fall back to
		// time-derived bytes so capture still works.
		now := time.Now().UnixNano()
		binary.BigEndian.PutUint64(b[0:8], uint64(now))
		binary.BigEndian.PutUint64(b[8:16], uint64(now)*2654435761)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// -----------------------------------------------------------------------------
// DSN parsing
// -----------------------------------------------------------------------------

type dsn struct {
	scheme    string
	publicKey string
	host      string
	basePath  string
}

func parseDSN(raw string) (*dsn, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("bugwatch: empty DSN")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("bugwatch: invalid DSN %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		// ok
	case "http":
		if !allowHTTP() {
			return nil, fmt.Errorf("bugwatch: insecure scheme %q refused (use HTTPS, or set BUGWATCH_ALLOW_HTTP=1 for tests)", u.Scheme)
		}
	default:
		return nil, fmt.Errorf("bugwatch: unsupported DSN scheme %q (want https://)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("bugwatch: DSN %q is missing a host", raw)
	}
	publicKey := ""
	if u.User != nil {
		publicKey = u.User.Username()
	}
	if publicKey == "" {
		return nil, fmt.Errorf("bugwatch: DSN %q is missing its public key", raw)
	}
	basePath := strings.TrimSuffix(u.Path, "/")
	return &dsn{scheme: u.Scheme, publicKey: publicKey, host: u.Host, basePath: basePath}, nil
}

// storeURL is the ingestion endpoint: <scheme>://<host><base>/store/
func (d *dsn) storeURL() string {
	return d.scheme + "://" + d.host + d.basePath + "/store/"
}

// -----------------------------------------------------------------------------
// Stacktrace capture
// -----------------------------------------------------------------------------

func readSourceLine(path string, line int) string {
	if path == "" || line <= 0 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 1<<20 {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if line-1 >= len(lines) {
		return ""
	}
	ctx := strings.TrimSpace(lines[line-1])
	if len(ctx) > maxSourceLineLen {
		ctx = ctx[:maxSourceLineLen]
	}
	return ctx
}

// captureStacktrace walks the calling goroutine's stack, skipping SDK-internal
// and runtime frames, innermost frame first.
func captureStacktrace(skip int) *Stacktrace {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(skip+1, pcs)
	if n == 0 {
		return nil
	}
	frames := runtime.CallersFrames(pcs[:n])
	var out []Frame
	for {
		f, more := frames.Next()
		fn := f.Function
		isSDK := strings.HasPrefix(fn, sdkModule+".") || strings.HasPrefix(fn, "runtime.")
		if !isSDK && f.File != "" {
			out = append(out, Frame{
				Filename:    f.File,
				Function:    fn,
				Lineno:      f.Line,
				ContextLine: readSourceLine(f.File, f.Line),
				InApp:       true,
			})
		}
		if !more {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	// runtime.CallersFrames yields outermost-first; Bugwatch wants crash-site first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return &Stacktrace{Frames: out}
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

// queueItem is one unit of work for the delivery worker. Flush barriers travel
// through the same FIFO queue as events, so closing a barrier channel proves
// every event enqueued before it was delivered.
type queueItem struct {
	event *Event
	flush chan struct{}
}

// Client captures events and delivers them asynchronously to a Bugwatch
// server. Use Init (package-level default client) or NewClient for explicit
// instances.
type Client struct {
	dsn      *dsn
	storeURL string
	http     *http.Client

	events chan queueItem
	done   chan struct{}

	mu          sync.RWMutex
	closed      bool
	breadcrumbs []Breadcrumb
	user        *User
	tags        map[string]string
	environment string
	release     string
}

// NewClient parses the DSN, validates it and starts the background delivery
// worker. It returns an error if the DSN is invalid or insecure.
func NewClient(dsnStr string) (*Client, error) {
	d, err := parseDSN(dsnStr)
	if err != nil {
		return nil, err
	}
	env := os.Getenv("BUGWATCH_ENVIRONMENT")
	if env == "" {
		env = "production"
	}
	c := &Client{
		dsn:         d,
		storeURL:    d.storeURL(),
		http:        &http.Client{Timeout: defaultHTTPTimeout},
		events:      make(chan queueItem, defaultQueueSize),
		done:        make(chan struct{}),
		tags:        make(map[string]string),
		environment: env,
		release:     os.Getenv("BUGWATCH_RELEASE"),
	}
	go c.worker()
	return c, nil
}

// worker drains queued items in FIFO order. Because flush barriers are queued
// behind the events enqueued before them, closing a barrier channel is proof
// that every earlier event was handed to the server (or failed over).
func (c *Client) worker() {
	for {
		select {
		case <-c.done:
			return
		case it := <-c.events:
			if it.flush != nil {
				close(it.flush)
				continue
			}
			if it.event != nil {
				c.send(it.event)
			}
		}
	}
}

// Close stops the background worker. Events still queued are dropped; call
// Flush first if they must be delivered.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	close(c.done)
}

// capture fills in defaults and context, applies redaction and enqueues the
// event without ever blocking the caller.
func (c *Client) capture(ev *Event) *Event {
	if ev.ID == "" {
		ev.ID = newEventID()
	}
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if ev.Platform == "" {
		ev.Platform = "go"
	}
	if ev.Level == "" {
		ev.Level = LevelError
	} else {
		ev.Level = normalizeLevel(ev.Level)
	}

	c.mu.RLock()
	ev.Environment = c.environment
	ev.Release = c.release
	if n := len(c.breadcrumbs); n > 0 {
		ev.Breadcrumbs = append([]Breadcrumb(nil), c.breadcrumbs...)
	}
	if len(c.tags) > 0 {
		ev.Tags = make(map[string]string, len(c.tags))
		for k, v := range c.tags {
			ev.Tags[k] = v
		}
	}
	if c.user != nil {
		u := *c.user
		ev.User = &u
	}
	c.mu.RUnlock()

	ev.applyRedaction()

	select {
	case c.events <- queueItem{event: ev}:
		return ev
	default:
		// Queue full: drop instead of blocking or allocating unboundedly.
		return nil
	}
}

// CaptureException captures an error as an "error"-level event with a
// stacktrace of the calling goroutine. It returns the enqueued event, or nil
// when no client is initialised or the queue is full. Never blocks.
func (c *Client) CaptureException(err error) *Event {
	if err == nil {
		return nil
	}
	value := err.Error()
	exc := &Exception{
		Type:       fmt.Sprintf("%T", err),
		Value:      value,
		Stacktrace: captureStacktrace(2), // skip captureStacktrace + CaptureException
	}
	return c.capture(&Event{Level: LevelError, Exception: exc})
}

// CaptureMessage captures a plain-text message with the given level.
func (c *Client) CaptureMessage(msg string, level string) *Event {
	return c.capture(&Event{Level: normalizeLevel(level), Message: msg})
}

// AddBreadcrumb appends a breadcrumb to the client-wide trail; the trail is
// attached to every subsequent event and keeps the most recent entries only.
func (c *Client) AddBreadcrumb(category, message string) {
	bc := Breadcrumb{
		Category:  category,
		Message:   message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.breadcrumbs = append(c.breadcrumbs, bc)
	if len(c.breadcrumbs) > maxBreadcrumbs {
		c.breadcrumbs = c.breadcrumbs[len(c.breadcrumbs)-maxBreadcrumbs:]
	}
}

// SetUser sets the user context attached to subsequent events.
func (c *Client) SetUser(id, email string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.user = &User{ID: id, Email: email}
}

// SetTag sets a tag attached to subsequent events. Setting the value of a
// user-related tag ("user.email", "email", "user.password", "password",
// "user.id", "id") to "sensitive" redacts that field from all outgoing
// events.
func (c *Client) SetTag(k, v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tags == nil {
		c.tags = make(map[string]string)
	}
	c.tags[k] = v
}

// Flush waits up to timeout for every event enqueued before the call to be
// delivered. It reports whether the queue drained in time.
func (c *Client) Flush(timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = time.Second
	}
	ch := make(chan struct{})
	select {
	case c.events <- queueItem{flush: ch}:
	case <-time.After(timeout):
		return false
	}
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

// send performs one synchronous HTTP delivery. Called only from the worker
// goroutine; failures are swallowed by design (error tracking must never take
// the host application down).
func (c *Client) send(ev *Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, c.storeURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bugwatch-Key", c.dsn.publicKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return
	}
	var out struct {
		EventID string `json:"event_id"`
		IssueID int64  `json:"issue_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return
	}
	ev.serverEventID = out.EventID
	ev.serverIssueID.Store(out.IssueID)
}

// -----------------------------------------------------------------------------
// Package-level default client
// -----------------------------------------------------------------------------

var (
	globalMu sync.RWMutex
	global   *Client
)

// Default returns the current package-level client set by Init, or nil.
func Default() *Client {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

// SetDefault installs c as the package-level client, closing any previous one.
func SetDefault(c *Client) {
	globalMu.Lock()
	old := global
	global = c
	globalMu.Unlock()
	if old != nil && old != c {
		old.Close()
	}
}

// Init parses the DSN, creates the package-level client and starts its
// background worker. Only https:// DSNs are accepted unless the environment
// variable BUGWATCH_ALLOW_HTTP=1 is set (tests/local development).
func Init(dsnStr string) error {
	c, err := NewClient(dsnStr)
	if err != nil {
		return err
	}
	SetDefault(c)
	return nil
}

// Close closes the package-level client, if any. Queued events are dropped;
// call Flush first.
func Close() {
	globalMu.Lock()
	old := global
	global = nil
	globalMu.Unlock()
	if old != nil {
		old.Close()
	}
}

// CaptureException captures err on the package-level client. See
// (*Client).CaptureException.
func CaptureException(err error) *Event {
	if c := Default(); c != nil {
		return c.CaptureException(err)
	}
	return nil
}

// CaptureMessage captures msg on the package-level client. See
// (*Client).CaptureMessage.
func CaptureMessage(msg string, level string) *Event {
	if c := Default(); c != nil {
		return c.CaptureMessage(msg, level)
	}
	return nil
}

// AddBreadcrumb records a breadcrumb on the package-level client.
func AddBreadcrumb(category, message string) {
	if c := Default(); c != nil {
		c.AddBreadcrumb(category, message)
	}
}

// SetUser sets the user context on the package-level client.
func SetUser(id, email string) {
	if c := Default(); c != nil {
		c.SetUser(id, email)
	}
}

// SetTag sets a tag on the package-level client.
func SetTag(k, v string) {
	if c := Default(); c != nil {
		c.SetTag(k, v)
	}
}

// Flush waits for the package-level client's queue to drain. Returns true
// immediately when no client is initialised.
func Flush(timeout time.Duration) bool {
	c := Default()
	if c == nil {
		return true
	}
	return c.Flush(timeout)
}
