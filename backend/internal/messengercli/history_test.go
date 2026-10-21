// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

import (
	"go.mau.fi/mautrix-meta/pkg/messagix/securehistory"
	"go.mau.fi/whatsmeow/proto/waArmadilloBackupCommon"
	"go.mau.fi/whatsmeow/proto/waArmadilloBackupMessage"
	"go.mau.fi/whatsmeow/proto/waMsgApplication"
	"google.golang.org/protobuf/proto"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryRequestsDeniedBeforeNetwork(t *testing.T) {
	b, _, _ := bridgeFixture(t)
	for _, r := range []bridgeRequest{{ChatID: "200", JID: "200@msgr", Limit: 10}, {ChatID: "100", JID: "wrong", Limit: 10}, {ChatID: "100", JID: "999@msgr", Limit: 51}, {ChatID: "100", JID: "999@msgr", Limit: 10, Before: -1}, {ChatID: "100", JID: "999@msgr", Limit: 10}, {ChatID: "400", JID: "400@msgr", Limit: 10}} {
		if _, e := b.fetchHistory(r); e == nil {
			t.Fatal("unsafe/unconfigured history accepted")
		}
		if b.cli != nil {
			t.Fatal("denied request reached network")
		}
	}
	for _, pin := range []string{"", "12", "secret", "１２３４５６", "1234567"} {
		if _, e := b.restoreHistory(pin); e == nil {
			t.Fatal("invalid PIN accepted")
		}
		if b.cli != nil {
			t.Fatal("invalid PIN reached network")
		}
	}
}
func TestArchiveTextIsReturnedWithoutPlaintextCaching(t *testing.T) {
	b, _, _ := bridgeFixture(t)
	chat, _ := b.chat("100")
	sub := &waMsgApplication.MessageApplication_SubProtocolPayload_ConsumerMessage{}
	if e := sub.Set(textMessage("older encrypted text")); e != nil {
		t.Fatal(e)
	}
	app := &waMsgApplication.MessageApplication{Payload: &waMsgApplication.MessageApplication_Payload{Content: &waMsgApplication.MessageApplication_Payload_SubProtocol{SubProtocol: &waMsgApplication.MessageApplication_SubProtocolPayload{SubProtocol: sub}}}}
	data, e := proto.Marshal(app)
	if e != nil {
		t.Fatal(e)
	}
	ts := time.Now().Add(-500 * 24 * time.Hour).UnixMilli()
	p := &waArmadilloBackupMessage.BackupMessage{Metadata: &waArmadilloBackupCommon.Metadata{SenderID: proto.String("123"), MessageID: proto.String("old-1"), TimestampMS: proto.Int64(ts)}, Payload: &waArmadilloBackupMessage.BackupMessage_EncryptedTransportMessage{EncryptedTransportMessage: data}}
	m := &securehistory.DecryptedMessage{Message: &securehistory.DecryptedProtobuf{Message: p, TimestampMS: ts}}
	got, e := archiveText(chat, m, 123)
	if e != nil || got == nil || got.Text != "older encrypted text" || !got.FromMe || got.Timestamp != ts {
		t.Fatalf("archive text conversion failed: %v", e)
	}
	if _, e = os.Stat(filepath.Join(b.state.dir, "messages.db")); !os.IsNotExist(e) {
		t.Fatal("history created a plaintext cache")
	}
	chat.Disappearing = true
	if got, e = archiveText(chat, m, 123); e != nil || got != nil {
		t.Fatal("disappearing archive returned")
	}
	chat.Disappearing = false
	p.Metadata.MessageID = nil
	if _, e = archiveText(chat, m, 123); e == nil {
		t.Fatal("missing metadata accepted")
	}
}
