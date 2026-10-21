// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func bridgeFixture(t *testing.T) (*bridgeBackend, bridgePolicy, func(bridgePolicy)) {
	t.Helper()
	s, e := openState(seedProfile(t))
	if e != nil {
		t.Fatal(e)
	}
	p := bridgePolicy{Version: 1, Permissions: []string{"read", "write"}, ConfirmSend: true, Chats: map[string]bridgeRule{"100": {Name: "Friend", Kind: "dm", JID: "999@msgr", Read: true, Write: true}, "300": {Name: "Group", Kind: "group", JID: "300@g.us", Read: true, Write: true, Group: true}, "400": {Name: "Ephemeral", Kind: "dm", JID: "400@msgr", Read: true, Write: true}}}
	path := filepath.Join(t.TempDir(), "policy.json")
	save := func(p bridgePolicy) {
		v, _ := json.Marshal(p)
		if e := os.WriteFile(path, v, 0600); e != nil {
			t.Fatal(e)
		}
	}
	save(p)
	b := &bridgeBackend{ctx: context.Background(), state: s, policyPath: path, global: map[string]bool{"read": true, "write": true}, idle: idleDisconnect}
	t.Cleanup(func() { s.Close() })
	return b, p, save
}
func TestBridgePermissionBindingBeforeNetwork(t *testing.T) {
	b, p, save := bridgeFixture(t)
	for _, r := range []bridgeRequest{{Op: "history", ChatID: "200", JID: "200@msgr", Limit: 1}, {Op: "send", ChatID: "100", JID: "wrong@msgr", Text: "hello"}, {Op: "history", ChatID: "300", JID: "300@g.us", Limit: 51}, {Op: "read", ChatID: "100", JID: "999@msgr", Limit: 1}} {
		if _, e := b.handle(r); e == nil {
			t.Fatal("unsafe request accepted")
		}
		if b.cli != nil {
			t.Fatal("denied request used network")
		}
	}
	p.Permissions = []string{"read"}
	save(p)
	if _, e := b.authorize("100", "write", "999@msgr"); e == nil {
		t.Fatal("global write revocation ignored")
	}
	p.Permissions = []string{"read", "write"}
	r := p.Chats["300"]
	r.Group = false
	p.Chats["300"] = r
	save(p)
	if _, e := b.policy(); e == nil {
		t.Fatal("group opt-in missing")
	}
}
func TestBridgeRemovesLegacyPlaintextCache(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"messages.db", "messages.db-journal", "messages.db-wal", "messages.db-shm"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte("old plaintext"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	keep := filepath.Join(dir, "account.json")
	if e := os.WriteFile(keep, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e := removeLegacyCache(dir); e != nil {
			t.Fatal(e)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "account.json" {
		t.Fatalf("unexpected profile contents after cleanup: %v", entries)
	}
}
func TestBridgeStatusDoesNotConnect(t *testing.T) {
	b, _, _ := bridgeFixture(t)
	v, e := b.serve(bridgeRequest{ID: 1, Op: "status"})
	if e != nil || b.cli != nil {
		t.Fatalf("status connected or failed: %v", e)
	}
	m := v.(map[string]any)
	if m["connection"] != "on_demand" || m["plaintext_saved"] != false || m["idle_disconnect_seconds"] != 120 {
		t.Fatalf("unexpected status: %v", m)
	}
}
func TestBridgeIdleDisconnect(t *testing.T) {
	b, _, _ := bridgeFixture(t)
	closed := 0
	b.closeConn = func(*session) error { closed++; return nil }
	b.cli = &session{}
	b.lastUsed = time.Now()
	if b.disconnectIfIdle(b.lastUsed.Add(idleDisconnect - time.Second)) {
		t.Fatal("disconnected before idle timeout")
	}
	if !b.disconnectIfIdle(b.lastUsed.Add(idleDisconnect)) || b.cli != nil || closed != 1 {
		t.Fatal("idle connection not closed")
	}
	if b.disconnectIfIdle(b.lastUsed.Add(time.Hour)) || closed != 1 {
		t.Fatal("closed twice")
	}
}
