# Bugwatch Go SDK

Official Bugwatch SDK for Go. Bugwatch is an error tracker: this SDK captures
exceptions and messages in your application and ships them asynchronously to
your Bugwatch server.

- **Zero external dependencies** — standard library only.
- **Non-blocking by design** — events are queued on an internal channel and
  sent by a background worker, so a slow or down Bugwatch server never stalls
  your application.
- **Privacy-aware** — user fields marked `sensitive` are redacted before the
  event leaves the process.

## Requirements

- Go 1.21 or newer.

## Installation

```sh
go get github.com/ycodexme/bugwatch-go
```

## Quick start

```go
package main

import (
	"errors"
	"log"

	bugwatch "github.com/ycodexme/bugwatch-go"
)

func main() {
	// DSN format: https://<public_key>@<host>/<path>
	if err := bugwatch.Init("https://bw-your_key@bugwatch-api.loadmindx.com/api/1"); err != nil {
		log.Fatalf("bugwatch init: %v", err)
	}
	defer bugwatch.Flush(5 * time.Second)

	err := doSomething()
	if err != nil {
		event := bugwatch.CaptureException(err)
		if event != nil {
			log.Printf("reported event %s", event.ID)
		}
	}
}
```

The DSN is the same string shown in your Bugwatch project settings. Only
`https://` is accepted; pass the environment variable `BUGWATCH_ALLOW_HTTP=1`
to allow plain HTTP for local development and tests.

## API

### `Init(dsn string) error`

Parses the DSN (`https://<public_key>@<host>/<base_path>`), validates that the
scheme is HTTPS (unless `BUGWATCH_ALLOW_HTTP=1`), creates the client and starts
the background delivery worker. Call it once at startup. Safe to call again:
it re-initialises the client with the new DSN.

### `CaptureException(err error) *Event`

Captures an error as an `error` level event. The exception type is derived from
the error's dynamic type (e.g. `*errors.errorString`) and its value from
`Error()`. A stacktrace of the calling goroutine is attached. Returns the
enqueued event, or `nil` if no client is initialised or the queue is full.
Never blocks.

### `CaptureMessage(msg string, level string) *Event`

Captures a plain text message with the given level (`"debug"`, `"info"`,
`"warning"`, `"error"`, `"fatal"`). Unknown levels are sent as `"error"`.

### `AddBreadcrumb(category, message string)`

Appends a breadcrumb (timestamped automatically) to the client-wide trail.
Breadcrumbs are attached to every subsequent event and the trail keeps the most
recent ones only.

### `SetUser(id, email string)`

Sets the user context attached to subsequent events.

### `SetTag(k, v string)`

Sets a tag attached to subsequent events.

### `Flush(timeout time.Duration) bool`

Waits up to `timeout` for all queued events to be delivered. Returns `true`
when the queue drained in time, `false` otherwise. Call it before your process
exits (e.g. in a `defer`) so buffered events are not lost.

## Event payload

Events are POSTed to `<dsn>/store/` with header `X-Bugwatch-Key:
<public_key>`:

```json
{
  "level": "error",
  "message": "...",
  "exception": {
    "type": "*errors.errorString",
    "value": "boom",
    "stacktrace": {
      "frames": [
        {"filename": "main.go", "function": "main.main", "lineno": 20, "colno": 9, "context_line": "panic(\"boom\")"}
      ]
    }
  },
  "timestamp": "2025-01-01T00:00:00Z",
  "environment": "production",
  "release": "",
  "platform": "go",
  "breadcrumbs": [{"category": "db", "message": "query users", "timestamp": "..."}],
  "tags": {"env": "prod"},
  "user": {"id": "42", "email": "[redacted]"},
  "request": {"url": "", "method": ""}
}
```

The server replies `200` with `{"event_id": "...", "issue_id": 123}`.

## Sensitive data

If you tag a user field `sensitive`, it is redacted before transmission:

```go
bugwatch.SetTag("user.email", "sensitive") // email is sent as "[redacted]"
```

Both `id` and `email` are checked against the tag map; anything tagged
`sensitive` never leaves the process in clear text.

## Environment variables

| Variable              | Effect                                            |
| --------------------- | ------------------------------------------------- |
| `BUGWATCH_ALLOW_HTTP` | Set to `1` to allow plain HTTP DSNs (tests only). |

## License

MIT — see [LICENSE](LICENSE).
