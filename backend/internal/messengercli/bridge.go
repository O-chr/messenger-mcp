// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

// Private local JSON-lines backend for the MCP server. The MCP client never
// receives this process' unrestricted CLI, credential files or policy editor.
import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type bridgeRule struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	JID   string `json:"jid"`
	Read  bool   `json:"read"`
	Write bool   `json:"write"`
	Group bool   `json:"group,omitempty"`
}
type bridgePolicy struct {
	Version     int                   `json:"version"`
	Permissions []string              `json:"permissions"`
	ConfirmSend bool                  `json:"confirm_send"`
	Chats       map[string]bridgeRule `json:"chats"`
}

func readBridgePolicy(path string) (bridgePolicy, error) {
	p := bridgePolicy{Version: 1, Permissions: []string{"read"}, ConfirmSend: true, Chats: map[string]bridgeRule{}}
	if err := privatePath(path, false); errors.Is(err, os.ErrNotExist) {
		return p, nil
	} else if err != nil {
		return p, errors.New("policy file is not private")
	}
	f, err := os.Open(path)
	if err != nil {
		return p, errors.New("cannot read policy")
	}
	defer f.Close()
	if st, e := f.Stat(); e != nil || st.Size() > 1024*1024 {
		return bridgePolicy{}, errors.New("invalid policy size")
	}
	p = bridgePolicy{}
	d := json.NewDecoder(io.LimitReader(f, 1024*1024))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || p.Version != 1 || !p.ConfirmSend || p.Chats == nil {
		return bridgePolicy{}, errors.New("invalid policy; all access denied")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return bridgePolicy{}, errors.New("invalid policy")
	}
	for id, r := range p.Chats {
		if id == "" || len(id) > 20 || strings.Trim(id, "0123456789") != "" || strings.HasPrefix(id, "0") || (r.Kind != "dm" && r.Kind != "group") || (r.Kind == "group" && !r.Group) {
			return bridgePolicy{}, errors.New("invalid policy rule")
		}
	}
	for _, perm := range p.Permissions {
		if perm != "read" && perm != "write" {
			return bridgePolicy{}, errors.New("invalid policy permissions")
		}
	}
	return p, nil
}
func (p bridgePolicy) permitted(id, perm string, c Chat, global map[string]bool) bool {
	permittedGlobally := false
	for _, v := range p.Permissions {
		if v == perm {
			permittedGlobally = true
		}
	}
	r, ok := p.Chats[id]
	if !ok || !global[perm] || !permittedGlobally || c.ID != id || r.JID != c.JID {
		return false
	}
	if c.Type.IsOneToOne() {
		if r.Kind != "dm" {
			return false
		}
	} else if r.Kind != "group" || !r.Group {
		return false
	}
	if perm == "read" {
		return r.Read
	}
	return perm == "write" && r.Write
}

// cachedMessage is one decrypted text returned to the MCP client. It is held in
// memory only; this backend never writes message bodies to disk.
type cachedMessage struct {
	ID        string `json:"id"`
	ChatID    string `json:"chat_id"`
	Sender    string `json:"sender_id"`
	FromMe    bool   `json:"from_me"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp_ms"`
	Source    string `json:"source"`
}

// idleDisconnect closes the Messenger connection after this long without a
// request. The backend connects only when a tool needs Meta instead of staying
// online as a resident receiver, so the account is not held open between uses.
const idleDisconnect = 2 * time.Minute

type bridgeBackend struct {
	ctx        context.Context
	state      *stateStore
	policyPath string
	global     map[string]bool
	idle       time.Duration
	// connMu serializes requests with the idle sweeper so a connection is never
	// closed while a history read or send is using it.
	connMu    sync.Mutex
	cli       *session
	lastUsed  time.Time
	closeConn func(*session) error
}

func (b *bridgeBackend) policy() (bridgePolicy, error) { return readBridgePolicy(b.policyPath) }
func (b *bridgeBackend) chat(id string) (Chat, error) {
	b.state.mu.Lock()
	defer b.state.mu.Unlock()
	c, ok := b.state.data.Chats[id]
	if !ok {
		return Chat{}, errors.New("chat unavailable")
	}
	return c, nil
}
func (b *bridgeBackend) authorize(id, perm, expected string) (Chat, error) {
	p, err := b.policy()
	if err != nil {
		return Chat{}, err
	}
	c, err := b.chat(id)
	if err != nil || !p.permitted(id, perm, c, b.global) || c.JID != expected {
		return Chat{}, errors.New("chat permission denied or target changed")
	}
	return c, nil
}
func (b *bridgeBackend) ensureOnline() error {
	if b.cli != nil && b.cli.e2ee != nil && b.cli.e2ee.IsLoggedIn() {
		return nil
	}
	b.disconnectLocked()
	ctx, cancel := context.WithTimeout(b.ctx, 60*time.Second)
	cli, err := loadSession(ctx, b.state, b.state.data.Cookies, b.state.data.Platform)
	cancel()
	if err != nil {
		return err
	}
	b.cli = cli
	// No live receiver and no auto-reconnect: incoming events are acknowledged
	// but never stored. Reads come from owner-enabled secure history on demand.
	cli.keepOnline = false
	if err = cli.connectE2EE(b.ctx, false); err != nil {
		return err
	}
	return nil
}
func (b *bridgeBackend) disconnectLocked() {
	if b.cli == nil {
		return
	}
	closeConn := b.closeConn
	if closeConn == nil {
		closeConn = (*session).close
	}
	_ = closeConn(b.cli)
	b.cli = nil
}
func (b *bridgeBackend) disconnectIfIdle(now time.Time) bool {
	b.connMu.Lock()
	defer b.connMu.Unlock()
	if b.cli == nil || now.Sub(b.lastUsed) < b.idle {
		return false
	}
	b.disconnectLocked()
	return true
}
func (b *bridgeBackend) serve(r bridgeRequest) (any, error) {
	b.connMu.Lock()
	defer b.connMu.Unlock()
	defer func() { b.lastUsed = time.Now() }()
	return b.handle(r)
}

// removeLegacyCache deletes the plaintext message cache that the former
// resident receiver kept for up to 7 days. On-demand mode has no such cache, so
// message bodies must not be left on disk after switching.
func removeLegacyCache(dir string) error {
	for _, name := range []string{"messages.db", "messages.db-journal", "messages.db-wal", "messages.db-shm"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot remove legacy message cache")
		}
	}
	return nil
}

type bridgeRequest struct {
	ID     int64  `json:"id"`
	Op     string `json:"op"`
	ChatID string `json:"chat_id,omitempty"`
	JID    string `json:"expected_jid,omitempty"`
	Text   string `json:"text,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Before int64  `json:"before_ms,omitempty"`
	PIN    string `json:"pin,omitempty"`
}
type bridgeResponse struct {
	ID     int64  `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (b *bridgeBackend) handle(r bridgeRequest) (any, error) {
	switch r.Op {
	case "status":
		_, err := b.policy()
		if err != nil {
			return nil, err
		}
		return map[string]any{"profile_exists": b.state.data.AccountID != 0, "connected": b.cli != nil && b.cli.e2ee != nil && b.cli.e2ee.IsLoggedIn(), "connection": "on_demand", "idle_disconnect_seconds": int(b.idle / time.Second), "message_history": "secure_history_on_demand", "history_ready": b.historyReady(), "plaintext_saved": false}, nil
	case "restore_history":
		return b.restoreHistory(r.PIN)
	case "history":
		return b.fetchHistory(r)
	case "send":
		if _, err := b.authorize(r.ChatID, "write", r.JID); err != nil {
			return nil, err
		}
		text, err := readMessage(strings.NewReader(r.Text), "", "", true)
		if err != nil {
			return nil, err
		}
		if err = b.ensureOnline(); err != nil {
			return nil, err
		}
		chat, err := b.authorize(r.ChatID, "write", r.JID)
		if err != nil {
			return nil, err
		}
		if _, err = b.state.resolve(r.ChatID); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(b.ctx, 60*time.Second)
		defer cancel()
		return b.cli.send(ctx, chat, text)
	default:
		return nil, errors.New("unsupported backend operation")
	}
}
func runBridge(ctx context.Context, args []string, dir string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("bridge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyPath := fs.String("policy", "", "owner-controlled policy file")
	permissions := fs.String("permissions", "read", "global permission ceiling")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *policyPath == "" {
		return errors.New("bridge requires --policy PATH and optional --permissions read,write")
	}
	global := map[string]bool{}
	for _, p := range strings.Split(*permissions, ",") {
		if p != "read" && p != "write" && p != "" {
			return errors.New("invalid global permissions")
		}
		global[p] = true
	}
	if dir == "" {
		var err error
		dir, err = defaultStateDir()
		if err != nil {
			return err
		}
	}
	s, err := openState(dir)
	if err != nil {
		return err
	}
	defer s.Close()
	if err = removeLegacyCache(s.dir); err != nil {
		return err
	}
	b := &bridgeBackend{ctx: ctx, state: s, policyPath: *policyPath, global: global, idle: idleDisconnect}
	defer func() {
		b.connMu.Lock()
		b.disconnectLocked()
		b.connMu.Unlock()
	}()
	// Nothing connects at startup. The sweeper only closes an idle connection.
	sweepCtx, stopSweep := context.WithCancel(ctx)
	sweepDone := make(chan struct{})
	defer func() { stopSweep(); <-sweepDone }()
	go func() {
		defer close(sweepDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sweepCtx.Done():
				return
			case now := <-ticker.C:
				b.disconnectIfIdle(now)
			}
		}
	}()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 128*1024)
	encoder := json.NewEncoder(out)
	for scanner.Scan() {
		var r bridgeRequest
		d := json.NewDecoder(strings.NewReader(scanner.Text()))
		d.DisallowUnknownFields()
		decodeErr := d.Decode(&r)
		var extra any
		if decodeErr != nil || r.ID <= 0 || d.Decode(&extra) != io.EOF {
			if encoder.Encode(bridgeResponse{Error: "invalid backend request"}) != nil {
				return nil
			}
			continue
		}
		result, e := b.serve(r)
		response := bridgeResponse{ID: r.ID, Result: result}
		if e != nil {
			response.Result = nil
			response.Error = e.Error()
		}
		if encoder.Encode(response) != nil {
			return nil
		}
	}
	if scanner.Err() != nil {
		return fmt.Errorf("backend input exceeded limits or closed unexpectedly")
	}
	return nil
}
