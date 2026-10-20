// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

// Private local JSON-lines backend for the MCP server. The MCP client never
// receives this process' unrestricted CLI, credential files or policy editor.
import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow/types/events"
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

type cachedMessage struct {
	ID        string `json:"id"`
	ChatID    string `json:"chat_id"`
	Sender    string `json:"sender_id"`
	FromMe    bool   `json:"from_me"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp_ms"`
	Source    string `json:"source"`
}
type bridgeBackend struct {
	ctx        context.Context
	state      *stateStore
	policyPath string
	global     map[string]bool
	cli        *session
	db         *sql.DB
	cacheMu    sync.Mutex
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
	if b.cli != nil {
		_ = b.cli.close()
		b.cli = nil
	}
	ctx, cancel := context.WithTimeout(b.ctx, 60*time.Second)
	cli, err := loadSession(ctx, b.state, b.state.data.Cookies, b.state.data.Platform)
	cancel()
	if err != nil {
		return err
	}
	b.cli = cli
	cli.onMessage = b.capture
	cli.keepOnline = true
	// Keep the E2EE receiver connected for this MCP process' lifetime.
	if err = cli.connectE2EE(b.ctx, false); err != nil {
		return err
	}
	return nil
}
func (b *bridgeBackend) openCache() error {
	p := filepath.Join(b.state.dir, "messages.db")
	if err := privatePath(p, false); errors.Is(err, os.ErrNotExist) {
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			return errors.New("cannot create message cache")
		}
		f.Close()
	} else if err != nil {
		return err
	}
	u := (&url.URL{Scheme: "file", Path: p}).String() + "?_busy_timeout=5000&_journal_mode=DELETE"
	db, err := sql.Open("sqlite3", u)
	if err != nil {
		return errors.New("cannot open message cache")
	}
	db.SetMaxOpenConns(1)
	b.db = db
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS messages (chat_id TEXT NOT NULL, id TEXT NOT NULL, sender TEXT NOT NULL, from_me INTEGER NOT NULL, body TEXT NOT NULL, timestamp_ms INTEGER NOT NULL, source TEXT NOT NULL, PRIMARY KEY(chat_id,id)); CREATE INDEX IF NOT EXISTS message_time ON messages(chat_id,timestamp_ms);`)
	if err != nil {
		return errors.New("cannot initialize message cache")
	}
	return nil
}
func (b *bridgeBackend) prune() error {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	return b.pruneLocked()
}
func (b *bridgeBackend) pruneLocked() error {
	p, err := b.policy()
	ids := []string{}
	args := []any{time.Now().Add(-7 * 24 * time.Hour).UnixMilli()}
	if err == nil {
		for _, c := range b.state.listChats() {
			if p.permitted(c.ID, "read", c, b.global) && !c.Disappearing {
				ids = append(ids, "?")
				args = append(args, c.ID)
			}
		}
	}
	query := "DELETE FROM messages WHERE timestamp_ms < ?"
	if len(ids) == 0 {
		query = "DELETE FROM messages"
		args = nil
	} else {
		query += " OR chat_id NOT IN (" + strings.Join(ids, ",") + ")"
	}
	if _, e := b.db.Exec(query, args...); e != nil {
		return errors.New("cannot prune private cache")
	}
	return nil
}
func (b *bridgeBackend) capture(evt *events.FBMessage) bool {
	if evt == nil {
		return true
	}
	p, err := b.policy()
	if err != nil {
		return b.prune() == nil
	}
	for _, chat := range b.state.listChats() {
		if chat.JID == evt.Info.Chat.ToNonAD().String() && p.permitted(chat.ID, "read", chat, b.global) {
			return b.storeEvent(chat, evt, "live") == nil
		}
	}
	return true
}
func (b *bridgeBackend) storeEvent(chat Chat, evt *events.FBMessage, source string) error {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	// Re-read on every event. Permissions can be revoked while a connection is open.
	if _, err := b.authorize(chat.ID, "read", chat.JID); err != nil {
		return b.pruneLocked()
	}
	if chat.Disappearing || evt.FBApplication.GetMetadata().GetEphemeral() != nil {
		return nil
	}
	content := evt.GetConsumerApplication().GetPayload().GetContent()
	if revoke := evt.GetConsumerApplication().GetPayload().GetApplicationData().GetRevoke(); revoke != nil {
		_, err := b.db.Exec("DELETE FROM messages WHERE chat_id=? AND id=?", chat.ID, revoke.GetKey().GetID())
		return err
	}
	if edit := content.GetEditMessage(); edit != nil {
		if len(edit.GetMessage().GetText()) > 16*1024 {
			return nil
		}
		_, err := b.db.Exec("UPDATE messages SET body=? WHERE chat_id=? AND id=? AND sender=?", edit.GetMessage().GetText(), chat.ID, edit.GetKey().GetID(), evt.Info.Sender.User)
		return err
	}
	text := content.GetMessageText()
	if text == nil || evt.Info.ID == "" || len(text.GetText()) > 16*1024 {
		return nil
	}
	if _, err := b.db.Exec(`INSERT INTO messages(chat_id,id,sender,from_me,body,timestamp_ms,source) VALUES(?,?,?,?,?,?,?) ON CONFLICT(chat_id,id) DO UPDATE SET body=excluded.body`, chat.ID, evt.Info.ID, evt.Info.Sender.User, evt.Info.IsFromMe, text.GetText(), evt.Info.Timestamp.UnixMilli(), source); err != nil {
		return errors.New("cannot persist allowed message")
	}
	_, err := b.db.Exec(`DELETE FROM messages WHERE chat_id=? AND id NOT IN (SELECT id FROM messages WHERE chat_id=? ORDER BY timestamp_ms DESC,id DESC LIMIT 500)`, chat.ID, chat.ID)
	return err
}
func (b *bridgeBackend) readMessages(id, jid string, limit int) ([]cachedMessage, error) {
	if _, err := b.authorize(id, "read", jid); err != nil {
		return nil, err
	}
	if err := b.prune(); err != nil {
		return nil, err
	}
	rows, err := b.db.Query("SELECT id,chat_id,sender,from_me,body,timestamp_ms,source FROM messages WHERE chat_id=? ORDER BY timestamp_ms DESC,id DESC LIMIT ?", id, limit)
	if err != nil {
		return nil, errors.New("cannot read message cache")
	}
	defer rows.Close()
	msgs := []cachedMessage{}
	for rows.Next() {
		var m cachedMessage
		if rows.Scan(&m.ID, &m.ChatID, &m.Sender, &m.FromMe, &m.Text, &m.Timestamp, &m.Source) != nil {
			return nil, errors.New("invalid cache record")
		}
		msgs = append(msgs, m)
	}
	if rows.Err() != nil {
		return nil, errors.New("cannot read message cache")
	}
	// Do not return a cached record if the owner revoked access during the query.
	if _, err = b.authorize(id, "read", jid); err != nil {
		return nil, err
	}
	return msgs, nil
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
		return map[string]any{"profile_exists": b.state.data.AccountID != 0, "connected": b.cli != nil && b.cli.e2ee != nil && b.cli.e2ee.IsLoggedIn(), "message_history": "live_cache_and_optional_secure_history", "history_ready": b.historyReady(), "retention_days": 7}, nil
	case "restore_history":
		return b.restoreHistory(r.PIN)
	case "history":
		return b.fetchHistory(r)
	case "read":
		if r.Limit < 1 || r.Limit > 50 {
			return nil, errors.New("limit must be 1-50")
		}
		if _, err := b.authorize(r.ChatID, "read", r.JID); err != nil {
			return nil, err
		}
		if err := b.ensureOnline(); err != nil {
			return nil, err
		}
		msgs, err := b.readMessages(r.ChatID, r.JID, r.Limit)
		return map[string]any{"chat_id": r.ChatID, "messages": msgs, "history": "live_cache_only; older backup history is not restored", "connected": true}, err
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
		result, err := b.cli.send(ctx, chat, text)
		if err == nil {
			// The sender may not receive its own live event. Only cache a confirmed
			// send when the separate read permission still allows the chat.
			b.cacheMu.Lock()
			if _, e := b.authorize(chat.ID, "read", chat.JID); e == nil {
				_, _ = b.db.Exec(`INSERT OR IGNORE INTO messages(chat_id,id,sender,from_me,body,timestamp_ms,source) VALUES(?,?,?,?,?,?,?)`, chat.ID, result.MessageID, b.state.data.AccountID, true, text, result.Timestamp.UnixMilli(), "sent_ack")
				_, _ = b.db.Exec(`DELETE FROM messages WHERE chat_id=? AND id NOT IN (SELECT id FROM messages WHERE chat_id=? ORDER BY timestamp_ms DESC,id DESC LIMIT 500)`, chat.ID, chat.ID)
			}
			b.cacheMu.Unlock()
		}
		return result, err
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
	b := &bridgeBackend{ctx: ctx, state: s, policyPath: *policyPath, global: global}
	if err = b.openCache(); err != nil {
		return err
	}
	defer b.db.Close()
	defer func() {
		if b.cli != nil {
			_ = b.cli.close()
		}
	}()
	if err = b.prune(); err != nil {
		return err
	}
	// Revocation erases plaintext cache promptly even when no tools are called.
	sweepCtx, stopSweep := context.WithCancel(ctx)
	sweepDone := make(chan struct{})
	defer func() { stopSweep(); <-sweepDone }()
	go func() {
		defer close(sweepDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sweepCtx.Done():
				return
			case <-ticker.C:
				_ = b.prune()
			}
		}
	}()
	p, policyErr := b.policy()
	if policyErr == nil && len(p.Chats) > 0 && (global["read"] || global["write"]) {
		_ = b.ensureOnline()
	}
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
		result, e := b.handle(r)
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
