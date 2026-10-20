// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

import (
	"context"
	"encoding/json"
	watypes "go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
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
	b := &bridgeBackend{ctx: context.Background(), state: s, policyPath: path, global: map[string]bool{"read": true, "write": true}}
	if e = b.openCache(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.db.Close(); s.Close() })
	return b, p, save
}
func fakeEvent(chat, id, text string) *events.FBMessage {
	jid, _ := watypes.ParseJID(chat)
	return &events.FBMessage{Info: watypes.MessageInfo{MessageSource: watypes.MessageSource{Chat: jid, Sender: watypes.NewJID("999", watypes.MessengerServer)}, ID: id, Timestamp: time.Now()}, Message: textMessage(text)}
}
func TestBridgePermissionBindingBeforeNetwork(t *testing.T) {
	b, p, save := bridgeFixture(t)
	for _, r := range []bridgeRequest{{Op: "read", ChatID: "200", JID: "200@msgr", Limit: 1}, {Op: "send", ChatID: "100", JID: "wrong@msgr", Text: "hello"}, {Op: "read", ChatID: "300", JID: "300@g.us", Limit: 51}} {
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
func TestBridgeCacheOnlyAllowedAndRevocationPurges(t *testing.T) {
	b, p, save := bridgeFixture(t)
	for _, chat := range []string{"999@msgr", "200@msgr", "400@msgr", "12345@msgr"} {
		if !b.capture(fakeEvent(chat, "message-1", "private")) {
			t.Fatal("capture failed")
		}
	}
	msgs, e := b.readMessages("100", "999@msgr", 10)
	if e != nil || len(msgs) != 1 || msgs[0].Text != "private" {
		t.Fatalf("allowed message missing %v", e)
	}
	var count int
	if e = b.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count); e != nil || count != 1 {
		t.Fatal("denied or disappearing message persisted")
	}
	r := p.Chats["100"]
	r.Read = false
	p.Chats["100"] = r
	save(p)
	if e = b.prune(); e != nil {
		t.Fatal(e)
	}
	if _, e = b.readMessages("100", "999@msgr", 10); e == nil {
		t.Fatal("revoked read accepted")
	}
	b.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if count != 0 {
		t.Fatal("revoked cache remains")
	}
}
func TestBridgeCacheBoundAndFailClosedPolicy(t *testing.T) {
	b, p, save := bridgeFixture(t)
	for i := 0; i < 502; i++ {
		evt := fakeEvent("999@msgr", time.Unix(int64(i), 0).Format(time.RFC3339), "text")
		if !b.capture(evt) {
			t.Fatal("capture failed")
		}
	}
	var count int
	b.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if count != 500 {
		t.Fatalf("cache cap: %d", count)
	}
	b.db.Exec("UPDATE messages SET timestamp_ms=?", time.Now().Add(-8*24*time.Hour).UnixMilli())
	if e := b.prune(); e != nil {
		t.Fatal(e)
	}
	b.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if count != 0 {
		t.Fatal("old cache retained")
	}
	b.capture(fakeEvent("999@msgr", "new", "secret"))
	p.ConfirmSend = false
	save(p)
	if _, e := b.policy(); e == nil {
		t.Fatal("invalid config accepted")
	}
	if e := b.prune(); e != nil {
		t.Fatal(e)
	}
	b.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if count != 0 {
		t.Fatal("invalid config did not purge")
	}
}
