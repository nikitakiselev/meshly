package pairing

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

const testKey2 = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="

func testHello() Hello {
	return Hello{Protocol: Protocol, Name: "homelab", WGPublicKey: testKey, Endpoint: netip.MustParseAddrPort("198.51.100.7:51820")}
}

func testWelcome() Welcome {
	return Welcome{
		NetworkID:   strings.Repeat("ab", 16),
		NetworkName: "mesh",
		CIDR:        netip.MustParsePrefix("10.100.0.0/24"),
		MTU:         1420,
		Inviter: Node{
			Name: "vps", Address: netip.MustParseAddr("10.100.0.1"),
			WGPublicKey: testKey2, Endpoint: netip.MustParseAddrPort("203.0.113.10:51820"),
		},
		Address: netip.MustParseAddr("10.100.0.2"),
	}
}

func soon() time.Time { return time.Now().Add(5 * time.Second) }

func TestJoinExchange(t *testing.T) {
	h, w, c := testHello(), testWelcome(), Confirm{WGPublicKey: testKey}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	errc := make(chan error, 1)
	go func() {
		req, err := ReadRequest(b, soon())
		if err == nil && (req.Hello == nil || *req.Hello != h) {
			err = errors.New("hello mismatch")
		}
		if err == nil {
			err = WriteWelcome(b, soon(), w)
		}
		errc <- err
	}()
	got, err := RequestJoin(a, soon(), h)
	if err != nil {
		t.Fatal(err)
	}
	if *got != w {
		t.Fatalf("welcome mismatch: %+v vs %+v", got, w)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}

	a2, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()
	go func() {
		req, err := ReadRequest(b2, soon())
		if err == nil && (req.Confirm == nil || *req.Confirm != c) {
			err = errors.New("confirm mismatch")
		}
		if err == nil {
			err = WriteOK(b2, soon())
		}
		errc <- err
	}()
	if err := SendConfirm(a2, soon(), c); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestRejectReachesJoiner(t *testing.T) {
	want := Reject{Reason: ReasonNameTaken, Message: `the name "vps" is already used`}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_, _ = ReadRequest(b, soon())
		_ = WriteReject(b, soon(), want)
	}()
	_, err := RequestJoin(a, soon(), testHello())
	var re *RejectError
	if !errors.As(err, &re) || re.Reject != want {
		t.Fatalf("got %v, want RejectError %+v", err, want)
	}
}

// feed returns a conn whose peer writes data and then closes (or stays
// silent when keepOpen is set).
func feed(t *testing.T, data string, keepOpen bool) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	go func() {
		_, _ = io.WriteString(b, data)
		if !keepOpen {
			b.Close()
		}
	}()
	return a
}

func TestHostilePeer(t *testing.T) {
	const (
		hello   = `{"name":"homelab","protocol":"meshly-pair/1","wg_public_key":"` + testKey + `"}`
		confirm = `{"wg_public_key":"` + testKey + `"}`
	)
	helloWith := func(body string) string { return `{"type":"hello","hello":` + body + `}` + "\n" }
	wl := testWelcome()
	toServer := map[string]string{
		"oversized line":    strings.Repeat("a", MaxMessageSize+1),
		"no newline":        `{"type":"ok"}`,
		"empty object":      "{}\n",
		"no body":           `{"type":"hello"}` + "\n",
		"two bodies":        `{"type":"hello","hello":` + hello + `,"confirm":` + confirm + `}` + "\n",
		"mismatched body":   `{"type":"hello","confirm":` + confirm + `}` + "\n",
		"ok to server":      `{"type":"ok"}` + "\n",
		"welcome to server": wire(t, message{Type: "welcome", Welcome: &wl}),
		"duplicate key":     `{"type":"hello","type":"hello","hello":` + hello + `}` + "\n",
		"unknown field":     helloWith(`{"x":1,"name":"homelab","protocol":"meshly-pair/1","wg_public_key":"` + testKey + `"}`),
		"capitalised key":   `{"Type":"hello","hello":` + hello + `}` + "\n",
		"bad name":          helloWith(`{"name":"Bad!","protocol":"meshly-pair/1","wg_public_key":"` + testKey + `"}`),
		"zero key":          helloWith(`{"name":"homelab","protocol":"meshly-pair/1","wg_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`),
		"port 0 endpoint":   helloWith(`{"name":"homelab","protocol":"meshly-pair/1","wg_public_key":"` + testKey + `","endpoint":"198.51.100.7:0"}`),
		"bad protocol":      helloWith(`{"name":"homelab","protocol":"meshly-pair/2","wg_public_key":"` + testKey + `"}`),
		"unknown type":      `{"type":"bye"}` + "\n",
		"deep nesting":      `{"type":"hello","hello":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}}}` + "\n",
		"trailing data":     `{"type":"ok"} x` + "\n",
	}
	for name, data := range toServer {
		t.Run("server/"+name, func(t *testing.T) {
			_, err := ReadRequest(feed(t, data, false), soon())
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("got %v, want ErrProtocol", err)
			}
		})
	}

	w := testWelcome()
	outside := w
	outside.Address = netip.MustParseAddr("10.200.0.2")
	same := w
	same.Address = w.Inviter.Address
	noEP := w
	noEP.Inviter.Endpoint = netip.AddrPort{}
	toClient := map[string]string{
		"welcome outside cidr": wire(t, message{Type: "welcome", Welcome: &outside}),
		"welcome same address": wire(t, message{Type: "welcome", Welcome: &same}),
		"welcome no endpoint":  wire(t, message{Type: "welcome", Welcome: &noEP}),
		"escape in reject":     `{"type":"reject","reject":{"reason":"invalid","message":"\u001b[2J"}}` + "\n",
		"unknown reason":       `{"type":"reject","reject":{"reason":"nope","message":"x"}}` + "\n",
		"long reject":          `{"type":"reject","reject":{"reason":"invalid","message":"` + strings.Repeat("a", 201) + `"}}` + "\n",
		"hello to client":      `{"type":"hello","hello":` + hello + `}` + "\n",
	}
	for name, data := range toClient {
		t.Run("client/"+name, func(t *testing.T) {
			conn := feedAfterRead(t, data)
			_, err := RequestJoin(conn, soon(), testHello())
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("got %v, want ErrProtocol", err)
			}
		})
	}

	t.Run("silent peer joiner", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		go io.Copy(io.Discard, b)
		_, err := RequestJoin(a, time.Now().Add(50*time.Millisecond), testHello())
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("got %v, want deadline exceeded", err)
		}
	})

	t.Run("silent peer", func(t *testing.T) {
		_, err := ReadRequest(feed(t, "", true), time.Now().Add(50*time.Millisecond))
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("got %v, want deadline exceeded", err)
		}
	})
}

// wire encodes m the way writeMessage does, bypassing validation.
func wire(t *testing.T, m message) string {
	t.Helper()
	b, err := marshalMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// feedAfterRead answers with data once the client has sent its hello.
func feedAfterRead(t *testing.T, data string) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	go func() {
		_, _ = ReadRequest(b, soon())
		_, _ = io.WriteString(b, data)
		b.Close()
	}()
	return a
}

func TestWriteRefusesInvalid(t *testing.T) {
	bad := testWelcome()
	bad.MTU = 1
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := WriteWelcome(a, soon(), bad); err == nil {
		t.Fatal("invalid welcome was written")
	}
	if err := WriteReject(a, soon(), Reject{Reason: ReasonInvalid, Message: "a\x00"}); err == nil {
		t.Fatal("non-printable reject was written")
	}
}

func TestMessageSizeBoundary(t *testing.T) {
	line := func(n int) string {
		h := testHello()
		base := wire(t, message{Type: "hello", Hello: &h})
		return strings.TrimSuffix(base, "\n") + strings.Repeat(" ", n-len(base)) + "\n"
	}
	if l := line(MaxMessageSize); len(l) != MaxMessageSize {
		t.Fatalf("test line is %d bytes", len(l))
	}
	req, err := ReadRequest(feed(t, line(MaxMessageSize), false), soon())
	if err != nil || req.Hello == nil {
		t.Fatalf("4096-byte line: %v", err)
	}
	_, err = ReadRequest(feed(t, line(MaxMessageSize+1), false), soon())
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("4097-byte line: got %v, want ErrProtocol", err)
	}
}
