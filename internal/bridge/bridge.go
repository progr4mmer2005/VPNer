// Package bridge defines the wire protocol between vpner.exe (Windows host)
// and vpner-agent (Linux, inside the dedicated WSL distro).
//
// Transport: a yamux session over the stdio of a long-running wsl.exe
// process. This deliberately avoids WSL networking entirely, so the bridge
// keeps working regardless of WSL network mode, host firewalls or kill
// switches of other VPN software.
//
// Every yamux stream starts with one JSON header line (Header). Depending on
// Op the stream then carries an RPC exchange, an event feed, a raw TCP pipe or
// framed UDP datagrams.
package bridge

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/hashicorp/yamux"
)

const ProtocolVersion = 1

// Stream operations.
const (
	OpRPC     = "rpc"     // host->agent: one request line, one response line
	OpEvents  = "events"  // host->agent: agent pushes Event lines forever
	OpDial    = "dial"    // both ways: TCP connect (host->agent: inside a connection netns; agent->host: real network)
	OpUDP     = "udp"     // both ways: UDP association, framed datagrams
	OpResolve = "resolve" // agent->host: resolve a hostname on the host
	OpOpenURL = "openurl" // agent->host: open URL in the user's browser (SSO)
)

type Header struct {
	Op   string `json:"op"`
	Conn string `json:"conn,omitempty"` // connection id (netns) for host->agent dial/udp
	Addr string `json:"addr,omitempty"` // host:port for dial
	Name string `json:"name,omitempty"` // hostname for resolve
	URL  string `json:"url,omitempty"`
}

// Reply is the first line written back on dial/udp/resolve streams.
type Reply struct {
	OK    bool     `json:"ok"`
	Error string   `json:"error,omitempty"`
	IPs   []string `json:"ips,omitempty"`
}

// ---- RPC ----

type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// ProcSpec is a generic description of a VPN daemon to run inside its own
// network namespace. Host-side providers build it; the agent knows nothing
// about specific VPN products, which keeps it generic and modular.
//
// Placeholders expanded by the agent in Argv, Files and Env values:
//
//	{{dir}}    per-connection runtime directory
//	{{socks}}  in-netns SOCKS5 uplink address (127.0.0.1:1080)
//	{{socksh}} uplink host part, {{socksp}} uplink port part
//	{{agent}}  path of the agent binary (for hook scripts)
//	{{id}}     connection id
type ProcSpec struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Argv        []string          `json:"argv"`
	Env         map[string]string `json:"env,omitempty"`
	Files       map[string]File   `json:"files,omitempty"` // relative to {{dir}}
	Answers     []Answer          `json:"answers,omitempty"`
	RouteAll    bool              `json:"routeAll"`              // force 0/1+128/1 via tunnel even if server pushes split routes
	FallbackDNS []string          `json:"fallbackDns,omitempty"` // used when the VPN does not push DNS
	Reconnect   bool              `json:"reconnect"`
	// UpPattern, if set, must appear in the daemon output (after the hook
	// reported the tunnel) before the connection counts as up. Some daemons
	// run their hooks before authentication has completed.
	UpPattern string `json:"upPattern,omitempty"`
	// DownPattern marks the tunnel down immediately when it appears in the
	// output (e.g. the daemon restarting internally).
	DownPattern string `json:"downPattern,omitempty"`
	// OpenVPNMgmt: the daemon is OpenVPN started with a management socket at
	// {{dir}}/mgmt.sock; the agent answers its credential and MFA queries
	// (static/dynamic challenge, private key password) through the UI.
	OpenVPNMgmt bool   `json:"openvpnMgmt,omitempty"`
	// ReachedPattern marks that the VPN server has answered; only then can a
	// silent wait after sending credentials mean "waiting for confirmation".
	ReachedPattern string `json:"reachedPattern,omitempty"`
	// PendingPattern means the server explicitly put the login on hold
	// (e.g. OpenVPN AUTH_PENDING): show "waiting for confirmation" at once.
	PendingPattern string `json:"pendingPattern,omitempty"`
	Creds       *Creds `json:"creds,omitempty"`
}

// Creds are saved credentials the agent may use without asking the user.
type Creds struct {
	User    string `json:"user,omitempty"`
	Pass    string `json:"pass,omitempty"`
	KeyPass string `json:"keyPass,omitempty"`
	// MFA answers a static challenge automatically (e.g. "push").
	MFA string `json:"mfa,omitempty"`
}

type File struct {
	Content string `json:"content"`
	Mode    uint32 `json:"mode,omitempty"`
}

// Answer auto-replies to an interactive prompt printed by the daemon.
type Answer struct {
	Pattern string `json:"pattern"` // Go regexp matched against the prompt text
	Value   string `json:"value"`
	Once    bool   `json:"once"`
	// Retry allows sending a Once answer again when the previous login
	// attempt failed only after a long wait: the server was waiting for a
	// confirmation (push) that did not come, the password itself was fine.
	Retry bool `json:"retry,omitempty"`
}

type ExecParams struct {
	Argv  []string          `json:"argv"`
	Env   map[string]string `json:"env,omitempty"`
	Stdin string            `json:"stdin,omitempty"`
}

type ExecResult struct {
	Code   int    `json:"code"`
	Output string `json:"output"`
}

type AnswerParams struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type ConnStatus struct {
	ID     string   `json:"id"`
	State  string   `json:"state"` // starting|auth|up|down|failed|stopped
	Detail string   `json:"detail,omitempty"`
	Tun    string   `json:"tun,omitempty"`
	IP     string   `json:"ip,omitempty"`
	DNS    []string `json:"dns,omitempty"`
	Since  int64    `json:"since"`
}

// ---- events ----

type Event struct {
	Type   string      `json:"type"` // log|state|prompt|openurl
	ID     string      `json:"id,omitempty"`
	Line   string      `json:"line,omitempty"`
	Status *ConnStatus `json:"status,omitempty"`
	Prompt string      `json:"prompt,omitempty"`
	Secret bool        `json:"secret,omitempty"`
	URL    string      `json:"url,omitempty"`
	Time   int64       `json:"time"`
}

// ---- helpers ----

func YamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.MaxStreamWindowSize = 4 << 20
	c.KeepAliveInterval = 15 * time.Second
	c.ConnectionWriteTimeout = 30 * time.Second
	c.StreamOpenTimeout = 30 * time.Second
	c.LogOutput = io.Discard
	return c
}

// WriteJSONLine writes v as a single JSON line.
func WriteJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// ReadJSONLine reads exactly one line from br into v.
func ReadJSONLine(br *bufio.Reader, v any) error {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// BufferedConn lets the remainder of a stream be read through the bufio.Reader
// used to parse the header, without losing buffered bytes.
type BufferedConn struct {
	net.Conn
	R *bufio.Reader
}

func (c *BufferedConn) Read(p []byte) (int, error) { return c.R.Read(p) }

// Open opens a stream with the given header and, for ops that answer with a
// Reply, waits for it.
func Open(s *yamux.Session, h Header) (*BufferedConn, *Reply, error) {
	st, err := s.OpenStream()
	if err != nil {
		return nil, nil, err
	}
	if err := WriteJSONLine(st, h); err != nil {
		st.Close()
		return nil, nil, err
	}
	bc := &BufferedConn{Conn: st, R: bufio.NewReaderSize(st, 32<<10)}
	switch h.Op {
	case OpDial, OpUDP, OpResolve, OpOpenURL:
		var r Reply
		st.SetReadDeadline(time.Now().Add(60 * time.Second))
		if err := ReadJSONLine(bc.R, &r); err != nil {
			st.Close()
			return nil, nil, err
		}
		st.SetReadDeadline(time.Time{})
		if !r.OK {
			st.Close()
			return nil, &r, errors.New(r.Error)
		}
		return bc, &r, nil
	}
	return bc, nil, nil
}

// Call performs a single RPC.
func Call(s *yamux.Session, method string, params any, result any) error {
	c, _, err := Open(s, Header{Op: OpRPC})
	if err != nil {
		return err
	}
	defer c.Close()
	req := Request{Method: method}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = b
	}
	if err := WriteJSONLine(c, req); err != nil {
		return err
	}
	var resp Response
	if err := ReadJSONLine(c.R, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if result != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, result)
	}
	return nil
}

// Pipe copies in both directions and closes both ends when done.
func Pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	cp := func(dst io.WriteCloser, src io.Reader) {
		buf := make([]byte, 64<<10)
		io.CopyBuffer(dst, src, buf)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// ---- UDP datagram framing ----
//
// frame := u16 length | addr | payload, where addr uses the SOCKS5 encoding
// (ATYP + address + u16 port).

const MaxDatagram = 65535

func WriteDatagram(w io.Writer, addr string, payload []byte) error {
	a, err := EncodeAddr(addr)
	if err != nil {
		return err
	}
	n := len(a) + len(payload)
	if n > MaxDatagram {
		return errors.New("datagram too large")
	}
	buf := make([]byte, 2+n)
	binary.BigEndian.PutUint16(buf, uint16(n))
	copy(buf[2:], a)
	copy(buf[2+len(a):], payload)
	_, err = w.Write(buf)
	return err
}

func ReadDatagram(r io.Reader, buf []byte) (addr string, payload []byte, err error) {
	var l [2]byte
	if _, err = io.ReadFull(r, l[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > len(buf) {
		return "", nil, errors.New("datagram buffer too small")
	}
	if _, err = io.ReadFull(r, buf[:n]); err != nil {
		return
	}
	addr, used, err := DecodeAddr(buf[:n])
	if err != nil {
		return
	}
	return addr, buf[used:n], nil
}

// EncodeAddr encodes host:port in SOCKS5 address format.
func EncodeAddr(hostport string) ([]byte, error) {
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("bad port in %q", hostport)
	}
	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			out = append([]byte{1}, ip4...)
		} else {
			out = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("hostname too long")
		}
		out = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(out, uint16(port)), nil
}

// DecodeAddr decodes a SOCKS5 address and returns it with the bytes consumed.
func DecodeAddr(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, errors.New("short address")
	}
	var host string
	var n int
	switch b[0] {
	case 1:
		if len(b) < 7 {
			return "", 0, errors.New("short ipv4 address")
		}
		host = net.IP(b[1:5]).String()
		n = 5
	case 4:
		if len(b) < 19 {
			return "", 0, errors.New("short ipv6 address")
		}
		host = net.IP(b[1:17]).String()
		n = 17
	case 3:
		if len(b) < 2 || len(b) < 2+int(b[1])+2 {
			return "", 0, errors.New("short domain address")
		}
		host = string(b[2 : 2+int(b[1])])
		n = 2 + int(b[1])
	default:
		return "", 0, fmt.Errorf("unknown address type %d", b[0])
	}
	port := binary.BigEndian.Uint16(b[n : n+2])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), n + 2, nil
}
