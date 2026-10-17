package pairing

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/nikitakiselev/meshly/internal/model"
)

const (
	// Protocol identifies the pairing protocol and its version.
	Protocol = "meshly-pair/1"
	// Port is the TCP pairing port, bound to the inviter's VPN address only.
	Port = 51820
	// MaxMessageSize bounds one wire message, newline included.
	MaxMessageSize = 4096

	maxRejectMessage = 200
)

// Timeouts are the per-phase deadlines of a pairing session.
type Timeouts struct{ Connect, Exchange, Confirm time.Duration }

// DefaultTimeouts are the production deadlines.
var DefaultTimeouts = Timeouts{Connect: 30 * time.Second, Exchange: 10 * time.Second, Confirm: time.Minute}

// Hello is the joiner's request.
type Hello struct {
	Protocol    string         `json:"protocol"`
	Name        string         `json:"name"`
	WGPublicKey string         `json:"wg_public_key"`
	Endpoint    netip.AddrPort `json:"endpoint,omitzero"`
}

// Node describes a mesh member.
type Node struct {
	Name        string         `json:"name"`
	Address     netip.Addr     `json:"address"`
	WGPublicKey string         `json:"wg_public_key"`
	Endpoint    netip.AddrPort `json:"endpoint"`
}

// Welcome is the inviter's answer to an accepted Hello.
type Welcome struct {
	NetworkID   string       `json:"network_id"`
	NetworkName string       `json:"network_name"`
	CIDR        netip.Prefix `json:"cidr"`
	MTU         int          `json:"mtu"`
	Inviter     Node         `json:"inviter"`
	Address     netip.Addr   `json:"address"` // assigned to the joiner
}

// Reject reasons.
const (
	ReasonNameTaken = "name-taken"
	ReasonUsed      = "used"
	ReasonInvalid   = "invalid"
)

// Reject refuses a join.
type Reject struct {
	Reason  string `json:"reason"`
	Message string `json:"message"` // printable ASCII, at most 200 bytes
}

// Confirm tells the inviter the joiner's final WireGuard key.
type Confirm struct {
	WGPublicKey string `json:"wg_public_key"`
}

// Validate checks an untrusted Hello.
func (h Hello) Validate() error {
	if h.Protocol != Protocol {
		return fmt.Errorf("unsupported protocol %q", truncateStr(h.Protocol))
	}
	if err := model.ValidateName(h.Name); err != nil {
		return err
	}
	if err := model.ValidateWGPublicKey(h.WGPublicKey); err != nil {
		return fmt.Errorf("wg_public_key: %w", err)
	}
	if h.Endpoint.IsValid() {
		if err := model.ValidateEndpoint(h.Endpoint); err != nil {
			return fmt.Errorf("endpoint: %w", err)
		}
	} else if h.Endpoint != (netip.AddrPort{}) {
		return errors.New("endpoint: invalid")
	}
	return nil
}

// Validate checks an untrusted Welcome.
func (w Welcome) Validate() error {
	if err := model.ValidateNetworkID(w.NetworkID); err != nil {
		return err
	}
	if err := model.ValidateName(w.NetworkName); err != nil {
		return err
	}
	if err := model.ValidateCIDR(w.CIDR); err != nil {
		return err
	}
	if err := model.ValidateMTU(w.MTU); err != nil {
		return err
	}
	n := w.Inviter
	if err := model.ValidateName(n.Name); err != nil {
		return fmt.Errorf("inviter: %w", err)
	}
	if err := model.ValidateWGPublicKey(n.WGPublicKey); err != nil {
		return fmt.Errorf("inviter wg_public_key: %w", err)
	}
	if err := model.ValidateEndpoint(n.Endpoint); err != nil {
		return fmt.Errorf("inviter endpoint: %w", err)
	}
	if err := model.ValidateHostAddress(w.CIDR, n.Address); err != nil {
		return fmt.Errorf("inviter address: %w", err)
	}
	if err := model.ValidateHostAddress(w.CIDR, w.Address); err != nil {
		return fmt.Errorf("address: %w", err)
	}
	if n.Address == w.Address {
		return errors.New("joiner and inviter addresses are equal")
	}
	return nil
}

// Validate checks an untrusted Reject.
func (r Reject) Validate() error {
	switch r.Reason {
	case ReasonNameTaken, ReasonUsed, ReasonInvalid:
	default:
		return fmt.Errorf("unknown reject reason %q", truncateStr(r.Reason))
	}
	if len(r.Message) > maxRejectMessage {
		return errors.New("reject message too long")
	}
	for i := 0; i < len(r.Message); i++ {
		if c := r.Message[i]; c < 0x20 || c > 0x7e {
			return errors.New("reject message must be printable ASCII")
		}
	}
	return nil
}

// Validate checks an untrusted Confirm.
func (c Confirm) Validate() error {
	if err := model.ValidateWGPublicKey(c.WGPublicKey); err != nil {
		return fmt.Errorf("wg_public_key: %w", err)
	}
	return nil
}

// Request is what the inviter reads: exactly one field is set.
type Request struct {
	Hello   *Hello
	Confirm *Confirm
}

// RejectError is returned to the joiner when the inviter refuses.
type RejectError struct{ Reject Reject }

func (e *RejectError) Error() string {
	return fmt.Sprintf("the inviter refused (%s): %s", e.Reject.Reason, e.Reject.Message)
}

// ErrProtocol wraps every malformed or unexpected peer message.
var ErrProtocol = errors.New("pairing protocol violation")

func violation(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, a...))
}

// message is the wire form: {"type":"<t>","<t>":{...}}.
type message struct {
	Type    string   `json:"type"`
	Hello   *Hello   `json:"hello,omitempty"`
	Welcome *Welcome `json:"welcome,omitempty"`
	Reject  *Reject  `json:"reject,omitempty"`
	Confirm *Confirm `json:"confirm,omitempty"`
}

func (m *message) validate() error {
	bodies := map[string]interface{ Validate() error }{}
	if m.Hello != nil {
		bodies["hello"] = m.Hello
	}
	if m.Welcome != nil {
		bodies["welcome"] = m.Welcome
	}
	if m.Reject != nil {
		bodies["reject"] = m.Reject
	}
	if m.Confirm != nil {
		bodies["confirm"] = m.Confirm
	}
	switch m.Type {
	case "ok":
		if len(bodies) != 0 {
			return violation("ok carries a body")
		}
		return nil
	case "hello", "welcome", "reject", "confirm":
		body, ok := bodies[m.Type]
		if !ok || len(bodies) != 1 {
			return violation("%s needs exactly one matching body", m.Type)
		}
		if err := body.Validate(); err != nil {
			return violation("%s: %v", m.Type, err)
		}
		return nil
	}
	return violation("unknown message type %q", truncateStr(m.Type))
}

func readMessage(conn net.Conn, deadline time.Time) (*message, error) {
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	line, err := bufio.NewReaderSize(conn, MaxMessageSize).ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return nil, violation("message longer than %d bytes", MaxMessageSize)
	case err != nil && len(line) > 0 && !isTimeout(err):
		return nil, violation("message not terminated by a newline")
	case err != nil:
		return nil, err
	}
	var m message
	if err := strictUnmarshal(bytes.TrimSuffix(line, []byte("\n")), &m); err != nil {
		return nil, violation("malformed message: %v", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func writeMessage(conn net.Conn, deadline time.Time, m message) error {
	if err := m.validate(); err != nil {
		return err
	}
	b, err := marshalMessage(m)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	_, err = conn.Write(b)
	return err
}

// marshalMessage returns the wire line, newline included.
func marshalMessage(m message) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(b)+1 > MaxMessageSize {
		return nil, fmt.Errorf("message larger than %d bytes", MaxMessageSize)
	}
	return append(b, '\n'), nil
}

// RequestJoin sends h and returns the inviter's Welcome; a refusal comes back
// as *RejectError.
func RequestJoin(conn net.Conn, deadline time.Time, h Hello) (*Welcome, error) {
	if err := writeMessage(conn, deadline, message{Type: "hello", Hello: &h}); err != nil {
		return nil, err
	}
	m, err := readMessage(conn, deadline)
	if err != nil {
		return nil, err
	}
	switch m.Type {
	case "welcome":
		return m.Welcome, nil
	case "reject":
		return nil, &RejectError{Reject: *m.Reject}
	}
	return nil, violation("unexpected %s reply to hello", m.Type)
}

// SendConfirm sends c and returns nil once the inviter answers "ok".
func SendConfirm(conn net.Conn, deadline time.Time, c Confirm) error {
	if err := writeMessage(conn, deadline, message{Type: "confirm", Confirm: &c}); err != nil {
		return err
	}
	m, err := readMessage(conn, deadline)
	if err != nil {
		return err
	}
	switch m.Type {
	case "ok":
		return nil
	case "reject":
		return &RejectError{Reject: *m.Reject}
	}
	return violation("unexpected %s reply to confirm", m.Type)
}

// ReadRequest reads the joiner's hello or confirm.
func ReadRequest(conn net.Conn, deadline time.Time) (*Request, error) {
	m, err := readMessage(conn, deadline)
	if err != nil {
		return nil, err
	}
	switch m.Type {
	case "hello":
		return &Request{Hello: m.Hello}, nil
	case "confirm":
		return &Request{Confirm: m.Confirm}, nil
	}
	return nil, violation("unexpected %s request", m.Type)
}

// WriteWelcome accepts the join.
func WriteWelcome(conn net.Conn, deadline time.Time, w Welcome) error {
	return writeMessage(conn, deadline, message{Type: "welcome", Welcome: &w})
}

// WriteReject refuses the join.
func WriteReject(conn net.Conn, deadline time.Time, r Reject) error {
	return writeMessage(conn, deadline, message{Type: "reject", Reject: &r})
}

// WriteOK acknowledges a confirm.
func WriteOK(conn net.Conn, deadline time.Time) error {
	return writeMessage(conn, deadline, message{Type: "ok"})
}
