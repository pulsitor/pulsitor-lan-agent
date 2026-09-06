package report

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/pulsitor/pulsitor-lan-agent/internal/config"
)

// identity stands in for an enrolled agent.
var identity = config.Identity{Code: "test-agent", Secret: "s3cret"}

// The canonical string is the contract with the server; if its shape drifts, every
// report starts failing authentication at once.
func TestCanonicalShape(t *testing.T) {
	got := string(Canonical("post", "/agent/v1/report", "1755500000", "abc", []byte(`{"a":1}`)))
	want := "1755500000\nabc\nPOST\n/agent/v1/report\n{\"a\":1}"

	if got != want {
		t.Fatalf("canonical string drifted:\n got %q\nwant %q", got, want)
	}
}

// Verified against the PHP side's hash_hmac('sha256', ...) for the same inputs.
func TestSignMatchesKnownVector(t *testing.T) {
	got := Sign("s3cret", Canonical("POST", "/agent/v1/report", "1755500000", "abc", []byte(`{"a":1}`)))
	want := "ef34ddb4654b2728c0ebe3f07ece8e0ea092431322d568d9829fffb3837f3e82"

	if got != want {
		t.Fatalf("signature drifted:\n got %s\nwant %s", got, want)
	}
}

// A report has to carry every header the server checks, and sign the body it actually
// sends rather than one built a second time.
func TestReportSignsWhatItSends(t *testing.T) {
	var (
		gotHeaders http.Header
		gotBody    []byte
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		buffer := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buffer)
		gotBody = buffer

		_, _ = w.Write([]byte(`{"config":{"discovery_interval_seconds":300,"subnets":["192.168.1.0/24"],"targets":[{"id":41,"ip":"192.168.1.10","interval_seconds":15}]}}`))
	}))
	defer server.Close()

	client := New(server.URL, "1.0.0")

	devices := []Device{{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff"}}

	runtime, err := client.Report(&identity, Report{
		ObservedAt: "2026-08-30T10:00:00Z",
		Devices:    &devices,
	})
	if err != nil {
		t.Fatalf("report: %v", err)
	}

	for _, header := range []string{"X-Pulsitor-Agent", "X-Pulsitor-Timestamp", "X-Pulsitor-Nonce", "X-Pulsitor-Signature"} {
		if gotHeaders.Get(header) == "" {
			t.Fatalf("%s was not sent", header)
		}
	}

	expected := Sign(identity.Secret, Canonical(
		http.MethodPost,
		"/agent/v1/report",
		gotHeaders.Get("X-Pulsitor-Timestamp"),
		gotHeaders.Get("X-Pulsitor-Nonce"),
		gotBody,
	))

	if gotHeaders.Get("X-Pulsitor-Signature") != expected {
		t.Fatal("the signature does not cover the body that was sent")
	}

	if runtime.DiscoveryIntervalSeconds != 300 || len(runtime.Subnets) != 1 {
		t.Fatalf("configuration was not read back: %+v", runtime)
	}

	if len(runtime.Targets) != 1 || runtime.Targets[0].ID != 41 || runtime.Targets[0].IntervalSeconds != 15 {
		t.Fatalf("targets were not read back: %+v", runtime.Targets)
	}
}

// Two reports must never reuse a nonce, or the second is refused as a replay.
func TestNoncesDoNotRepeat(t *testing.T) {
	seen := map[string]bool{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get("X-Pulsitor-Nonce")
		if seen[nonce] {
			t.Errorf("nonce %s was reused", nonce)
		}
		seen[nonce] = true

		_, _ = w.Write([]byte(`{"config":{}}`))
	}))
	defer server.Close()

	client := New(server.URL, "1.0.0")

	for range 5 {
		if _, err := client.Report(&identity, Report{ObservedAt: "2026-08-30T10:00:00Z"}); err != nil {
			t.Fatalf("report: %v", err)
		}
	}
}

// The server's own error code is what an operator needs to see, not a bare status.
func TestServerErrorCodeIsSurfaced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"nonce_replayed","message":"Nonce has already been used."}`))
	}))
	defer server.Close()

	_, err := New(server.URL, "1.0.0").Report(&identity, Report{ObservedAt: "2026-08-30T10:00:00Z"})

	if err == nil || !strings.Contains(err.Error(), "nonce_replayed") {
		t.Fatalf("expected the server's code in the error, got %v", err)
	}
}

// A round in which discovery did not run must omit the inventory keys entirely, and a
// discovery that found nothing must still send them as empty lists. The server tells
// "did not run" from "ran and found nothing" by their presence alone: the first has to
// leave the inventory untouched, the second has to age it out.
func TestDiscoveryPresenceIsDistinguishable(t *testing.T) {
	bodies := [][]byte{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buffer := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buffer)
		bodies = append(bodies, buffer)
		_, _ = w.Write([]byte(`{"config":{}}`))
	}))
	defer server.Close()

	client := New(server.URL, "1.0.0")

	if _, err := client.Report(&identity, Report{
		ObservedAt:   "x",
		Observations: []Observation{{ID: 7, Online: true, IP: "192.168.1.10"}},
	}); err != nil {
		t.Fatalf("probe-only report: %v", err)
	}

	empty := []Device{}
	interfaces := []Interface{}

	if _, err := client.Report(&identity, Report{
		ObservedAt: "x",
		Devices:    &empty,
		Interfaces: &interfaces,
	}); err != nil {
		t.Fatalf("empty discovery report: %v", err)
	}

	probeOnly := decode(t, bodies[0])

	if _, ok := probeOnly["devices"]; ok {
		t.Fatalf("a probe-only round must not carry devices: %s", bodies[0])
	}
	if _, ok := probeOnly["interfaces"]; ok {
		t.Fatalf("a probe-only round must not carry interfaces: %s", bodies[0])
	}
	if string(probeOnly["observations"]) == "" {
		t.Fatalf("observations were not sent: %s", bodies[0])
	}

	discovery := decode(t, bodies[1])

	if string(discovery["devices"]) != "[]" || string(discovery["interfaces"]) != "[]" {
		t.Fatalf("an empty discovery did not serialise as lists: %s", bodies[1])
	}
}

// decode unmarshals a request body into its top-level keys.
func decode(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()

	decoded := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body was not JSON: %v", err)
	}

	return decoded
}

// The server's refusals are not all the same shape of problem, and treating them alike
// means either hammering a door that will never open or giving up on one that will.
func TestServerErrorClassifiesRefusals(t *testing.T) {
	for _, testCase := range []struct {
		code     string
		terminal bool
		advises  bool
	}{
		{"agent_mismatch", true, true},
		{"signature_invalid", true, true},
		{"timestamp_out_of_window", false, true},
		{"token_invalid", false, true},
		{"nonce_replayed", false, false},
		{"", false, false},
	} {
		failure := &ServerError{Status: 401, Code: testCase.code, Message: "no"}

		if failure.Terminal() != testCase.terminal {
			t.Fatalf("%q: terminal = %v, want %v", testCase.code, failure.Terminal(), testCase.terminal)
		}

		if (failure.Advice() != "") != testCase.advises {
			t.Fatalf("%q: advice = %q", testCase.code, failure.Advice())
		}
	}
}

func TestServerErrorReadsWithAndWithoutACode(t *testing.T) {
	if got := (&ServerError{Status: 502}).Error(); got != "server returned HTTP 502" {
		t.Fatalf("got %q", got)
	}

	if got := (&ServerError{Status: 401, Code: "agent_mismatch"}).Error(); got != "server refused the request: agent_mismatch" {
		t.Fatalf("got %q", got)
	}

	got := (&ServerError{Status: 401, Code: "agent_mismatch", Message: "Unknown agent."}).Error()
	if got != "server refused the request: agent_mismatch (Unknown agent.)" {
		t.Fatalf("got %q", got)
	}
}

// The classification is worthless unless a real refusal actually arrives as this type.
func TestRefusalsArriveAsServerErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"agent_mismatch","message":"Unknown agent."}`))
	}))
	defer server.Close()

	client := New(server.URL, "test")

	_, err := client.Report(&config.Identity{Code: "a", Secret: "b"}, Report{})

	var refusal *ServerError
	if !errors.As(err, &refusal) {
		t.Fatalf("expected a *ServerError, got %T: %v", err, err)
	}

	if !refusal.Terminal() || refusal.Status != http.StatusUnauthorized {
		t.Fatalf("unexpected refusal: %+v", refusal)
	}
}

// An operator reading the server's access log has nothing else to identify the fleet by.
func TestRequestsIdentifyThemselves(t *testing.T) {
	seen := make(chan string, 2)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`{"agent_code":"a","agent_secret":"b","config":{}}`))
	}))
	defer server.Close()

	client := New(server.URL, "1.2.3")

	if _, err := client.Enroll("token"); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	agent := <-seen

	if !strings.HasPrefix(agent, "pulsitor-lan-agent/1.2.3 (") {
		t.Fatalf("unexpected User-Agent %q", agent)
	}

	if !strings.Contains(agent, runtime.GOOS) || !strings.Contains(agent, runtime.GOARCH) {
		t.Fatalf("the User-Agent does not name the platform: %q", agent)
	}
}
