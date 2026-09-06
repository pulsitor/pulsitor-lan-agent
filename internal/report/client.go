// Package report speaks the agent half of the Pulsitor agent protocol.
package report

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pulsitor/pulsitor-lan-agent/internal/config"
)

// Device is one host discovery saw.
type Device struct {
	MAC      string `json:"mac,omitempty"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
}

// Interface is a network the agent found itself attached to.
type Interface struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

// Observation is the result of one targeted probe: whether the device answered, and
// the address it answered at. Nothing here is a verdict — how many misses amount to an
// outage, and whether a new address is worth an incident, are the server's to decide.
type Observation struct {
	ID       int64  `json:"id"`
	Online   bool   `json:"online"`
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// Report is one round of the agent's work.
//
// Discovery and monitoring travel together but are separate: most rounds carry probe
// results only, because discovery runs on its own much slower clock.
type Report struct {
	Contract   int    `json:"contract"`
	Version    string `json:"version"`
	ObservedAt string `json:"observed_at"`

	// Interfaces and Devices are pointers so that "discovery ran and found nothing"
	// can be told apart from "discovery did not run this round". The first has to age
	// out the inventory; the second must leave it untouched. Discovery is also always
	// a full picture rather than a diff, so a report replayed after a dropped
	// connection leaves the inventory unchanged instead of half-applied.
	Interfaces *[]Interface `json:"interfaces,omitempty"`
	Devices    *[]Device    `json:"devices,omitempty"`

	// Scanned names the networks this round genuinely covered. Absence from Devices
	// only means a device is gone if its network is named here; anywhere else it means
	// the agent never looked, and the server must leave those devices alone rather than
	// declare a whole subnet dead because one sweep came back short.
	Scanned *[]string `json:"scanned,omitempty"`

	Observations []Observation `json:"observations,omitempty"`
}

// DefaultServer is the Pulsitor installation a released binary reports to.
//
// Compiled in rather than configured. An agent is installed by a customer who was given
// a token and nothing else: an endpoint they have to type is one they can mistype, and a
// wrong one is an agent that enrolls nowhere and a support conversation. It also means
// the service definition carries no endpoint, so there is no file on the customer's
// machine that can be edited to point the agent somewhere else.
//
// The --server flag still overrides it, for running against a development server.
const DefaultServer = "https://external-services.pulsitor.com"

// Client posts to one Pulsitor installation.
type Client struct {
	BaseURL string
	Version string
	HTTP    *http.Client
}

// New builds a client with a timeout short enough that a hung server cannot stall the
// sweep loop indefinitely.
func New(baseURL, version string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Version: version,
		HTTP:    &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

// Enroll trades a one-time token for the agent's permanent identity.
func (c *Client) Enroll(token string) (*config.Identity, error) {
	if err := ValidateURL(c.BaseURL); err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"enrollment_token": token})

	request, err := http.NewRequest(http.MethodPost, c.BaseURL+"/agent/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.identify(request)

	raw, err := c.do(request)
	if err != nil {
		return nil, err
	}

	identity := &config.Identity{}
	if err := json.Unmarshal(raw, identity); err != nil {
		return nil, err
	}
	if identity.Code == "" || identity.Secret == "" {
		return nil, fmt.Errorf("enrollment response carried no identity")
	}

	return identity, nil
}

// Report sends one round of work and returns the configuration to run on until the
// next one.
func (c *Client) Report(identity *config.Identity, report Report) (*config.Runtime, error) {
	return c.ReportContext(context.Background(), identity, report)
}

func (c *Client) ReportContext(ctx context.Context, identity *config.Identity, report Report) (*config.Runtime, error) {
	if err := ValidateURL(c.BaseURL); err != nil {
		return nil, err
	}
	if identity == nil || identity.Code == "" || identity.Secret == "" {
		return nil, fmt.Errorf("missing agent identity")
	}
	report.Contract = 1
	report.Version = c.Version

	body, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}

	endpoint := c.BaseURL + "/agent/v1/report"

	path, err := requestPath(endpoint)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.identify(request)

	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	request.Header.Set("X-Pulsitor-Agent", identity.Code)
	request.Header.Set("X-Pulsitor-Timestamp", timestamp)
	request.Header.Set("X-Pulsitor-Nonce", nonce)
	request.Header.Set("X-Pulsitor-Signature", Sign(identity.Secret, Canonical(http.MethodPost, path, timestamp, nonce, body)))

	raw, err := c.do(request)
	if err != nil {
		return nil, err
	}

	response := struct {
		Config *config.Runtime `json:"config"`
	}{}
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, err
	}

	if response.Config == nil {
		return nil, fmt.Errorf("response has no configuration")
	}
	if err := response.Config.Validate(); err != nil {
		return nil, err
	}
	return response.Config, nil
}

// Canonical builds the string both ends sign. The method and path travel with the body
// so a captured report cannot be replayed against a different endpoint.
func Canonical(method, path, timestamp, nonce string, body []byte) []byte {
	out := make([]byte, 0, len(body)+len(path)+len(timestamp)+len(nonce)+16)
	out = append(out, timestamp...)
	out = append(out, '\n')
	out = append(out, nonce...)
	out = append(out, '\n')
	out = append(out, strings.ToUpper(method)...)
	out = append(out, '\n')
	out = append(out, path...)
	out = append(out, '\n')

	return append(out, body...)
}

// Sign returns the lower-case hex HMAC the server re-computes to authenticate us.
func Sign(secret string, canonical []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(canonical)

	return hex.EncodeToString(mac.Sum(nil))
}

// requestPath is the path alone: the query string is not part of what is signed.
func requestPath(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}

	return parsed.Path, nil
}

// newNonce returns a value the server will not have seen before.
func newNonce() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	return hex.EncodeToString(buffer), nil
}

// do executes a request and turns a non-2xx into the server's own error code, which is
// what the operator needs to see in the log.
func (c *Client) do(request *http.Request) ([]byte, error) {
	response, err := c.HTTP.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}

	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("response exceeds 1 MiB")
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		failure := struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}{}
		_ = json.Unmarshal(raw, &failure)

		return nil, &ServerError{
			Status:  response.StatusCode,
			Code:    failure.Code,
			Message: failure.Message,
		}
	}

	return raw, nil
}

// identify sets the headers every request carries.
//
// The User-Agent is what an operator reading the server's access log has to work with
// when a fleet of agents starts behaving oddly, and it is the only place the running
// build is written down.
func (c *Client) identify(request *http.Request) {
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "pulsitor-lan-agent/"+c.version()+" ("+runtime.GOOS+"/"+runtime.GOARCH+")")
}

// version is the build stamp, or a placeholder when the binary was built without one.
func (c *Client) version() string {
	if c.Version == "" {
		return "dev"
	}

	return c.Version
}

// Credentials must only travel over TLS. Literal loopback HTTP supports local development.
func ValidateURL(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("invalid server URL")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("server URL must contain only scheme, host and optional path")
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("server URL requires HTTPS (HTTP is allowed only on literal loopback addresses)")
}

// ServerError is a refusal the server explained, kept as a type so the agent can tell
// the three kinds apart: something it can wait out, something the operator has to fix,
// and something that will never work again however long it retries.
type ServerError struct {
	Status  int
	Code    string
	Message string
}

func (e *ServerError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("server returned HTTP %d", e.Status)
	}

	if e.Message == "" {
		return fmt.Sprintf("server refused the request: %s", e.Code)
	}

	return fmt.Sprintf("server refused the request: %s (%s)", e.Code, e.Message)
}

// Terminal reports whether retrying this could ever succeed.
//
// An agent whose identity the owner deleted, or whose secret no longer matches, is done:
// every subsequent report is refused identically. It keeps running rather than exiting —
// a service manager would only restart it into the same wall, and each restart is
// another request the server has to refuse — but it stops climbing its backoff and says
// plainly what a person has to do.
func (e *ServerError) Terminal() bool {
	switch e.Code {
	case "agent_mismatch", "signature_invalid":
		return true
	default:
		return false
	}
}

// Advice is what the operator should do about it, where there is something to do.
func (e *ServerError) Advice() string {
	switch e.Code {
	case "agent_mismatch", "signature_invalid":
		return "this agent's identity is no longer accepted; delete the state file and enrol again from Pulsitor"
	case "timestamp_out_of_window":
		return "this machine's clock is too far from the server's; enable NTP time synchronisation"
	case "token_invalid", "token_missing":
		return "the enrollment token is unknown, expired or already used; issue a new one in Pulsitor"
	default:
		return ""
	}
}
