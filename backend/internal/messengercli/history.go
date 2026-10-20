// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.mau.fi/mautrix-meta/pkg/messagix/securehistory"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waArmadilloBackupMessage"
	"go.mau.fi/whatsmeow/proto/waMsgApplication"
	watypes "go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

func (b *bridgeBackend) historyReady() bool {
	b.state.mu.Lock()
	defer b.state.mu.Unlock()
	return b.state.data.HistoryDevice != nil && b.state.data.HistoryDevice.ID != ""
}
func (b *bridgeBackend) restoreHistory(pinText string) (any, error) {
	if len(pinText) != 6 || strings.Trim(pinText, "0123456789") != "" {
		return nil, errors.New("Enter the six-digit secure storage PIN in the owner setup page.")
	}
	if b.historyReady() {
		return map[string]any{"history_ready": true}, nil
	}
	b.state.mu.Lock()
	pending := b.state.data.HistoryDevice != nil
	b.state.mu.Unlock()
	if pending {
		return nil, errors.New("Previous history enrollment is unconfirmed. Do not retry; check Messenger before recovery.")
	}
	p, e := b.policy()
	if e != nil {
		return nil, e
	}
	readable := false
	for _, c := range b.state.listChats() {
		if p.permitted(c.ID, "read", c, b.global) {
			readable = true
			break
		}
	}
	if !readable {
		return nil, errors.New("History setup requires an allowed readable chat.")
	}
	if e = b.ensureOnline(); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(b.ctx, 80*time.Second)
	defer cancel()
	h := b.cli.web.GetSecureHistoryClient()
	backup, e := h.GetBackup(ctx)
	if errors.Is(e, securehistory.ErrNoPINBackup) {
		return nil, errors.New("No PIN-protected secure storage backup was found. Check Messenger secure storage on your phone.")
	}
	if e != nil {
		return nil, errors.New("Could not inspect secure storage. No PIN recovery was attempted.")
	}
	pin := []byte(pinText)
	defer clear(pin)
	recovery, e := h.RecoverPIN(ctx, backup, pin)
	if e != nil {
		var re *securehistory.RecoveryError
		if errors.As(e, &re) && re.AttemptsRemaining != nil {
			return nil, fmt.Errorf("PIN recovery failed; Messenger reports %d attempts remaining. No automatic retry.", *re.AttemptsRemaining)
		}
		return nil, errors.New("PIN recovery failed. Check the PIN; no automatic retry.")
	}
	virtual, e := h.GetVirtualDevice(ctx, backup, b.state.data.AccountID, recovery.Code)
	if e != nil {
		return nil, errors.New("Could not recover the backup device. PIN was not saved.")
	}
	epochs, e := virtual.DeriveEpochs()
	if e != nil {
		return nil, errors.New("Could not derive secure history keys.")
	}
	enrollment, e := virtual.PrepareDevice(backup.ID, h.RegistrationID, b.cli.e2ee.Store.IdentityKey, epochs)
	if e != nil {
		return nil, errors.New("Could not prepare secure history enrollment.")
	}
	b.state.mu.Lock()
	b.state.data.HistoryDevice = enrollment.Device
	b.state.mu.Unlock()
	if e = b.state.save(); e != nil {
		b.state.mu.Lock()
		b.state.data.HistoryDevice = nil
		b.state.mu.Unlock()
		return nil, errors.New("Could not save pending enrollment; no registration was attempted.")
	}
	device, e := h.AddDevice(ctx, enrollment)
	if e != nil {
		var rejected *securehistory.EnrollmentError
		if errors.As(e, &rejected) {
			b.state.mu.Lock()
			b.state.data.HistoryDevice = nil
			b.state.mu.Unlock()
			_ = b.state.save()
			return nil, errors.New("Messenger rejected history enrollment. PIN was not saved.")
		}
		return nil, errors.New("History enrollment outcome is unknown. Do not retry automatically.")
	}
	b.state.mu.Lock()
	b.state.data.HistoryDevice = device
	b.state.mu.Unlock()
	if e = b.state.save(); e != nil {
		return nil, errors.New("Enrollment succeeded but saving keys failed. Do not repeat PIN recovery.")
	}
	return map[string]any{"history_ready": true, "pin_saved": false}, nil
}
func (b *bridgeBackend) fetchHistory(r bridgeRequest) (any, error) {
	if r.Limit < 1 || r.Limit > 50 || r.Before < 0 || r.Before > 1<<48-1 {
		return nil, errors.New("Invalid history range.")
	}
	chat, e := b.authorize(r.ChatID, "read", r.JID)
	if e != nil {
		return nil, e
	}
	if chat.Disappearing || !chat.Type.IsWhatsApp() {
		return nil, errors.New("Secure history is available only for supported non-disappearing E2EE chats.")
	}
	if !b.historyReady() {
		return nil, errors.New("Secure history setup is required. Enter the PIN only in the owner setup page, never in chat.")
	}
	if e = b.ensureOnline(); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(b.ctx, 70*time.Second)
	defer cancel()
	b.state.mu.Lock()
	device := b.state.data.HistoryDevice
	b.state.mu.Unlock()
	jid, e := watypes.ParseJID(chat.JID)
	if e != nil {
		return nil, errors.New("Invalid history chat address.")
	}
	before := r.Before
	if before == 0 {
		before = time.Now().Add(time.Minute).UnixMilli()
	}
	page, e := b.cli.web.GetSecureHistoryClient().FetchMessages(ctx, device, jid.User, true, before, r.Limit)
	if e != nil {
		return nil, errors.New("Could not fetch the secure history range. Check Messenger storage availability.")
	}
	if *page.Range.HasMoreBefore && page.Range.Before >= before {
		return nil, errors.New("History cursor did not move backwards.")
	}
	if page.Epochs != nil && len(page.Epochs.Edges) > 0 {
		device, e = device.WithEpochs(page.Epochs)
		if e != nil {
			return nil, errors.New("Could not derive older history epochs.")
		}
		b.state.mu.Lock()
		b.state.data.HistoryDevice = device
		b.state.mu.Unlock()
		if e = b.state.save(); e != nil {
			return nil, e
		}
	}
	if _, e = b.authorize(r.ChatID, "read", r.JID); e != nil {
		return nil, e
	}
	decrypted, e := page.Decrypt(device, jid.User, b.state.data.AccountID, jid.Server == watypes.GroupServer)
	if e != nil {
		return nil, errors.New("Secure history decryption failed; no partial plaintext returned.")
	}
	result := []cachedMessage{}
	for _, m := range decrypted {
		msg, e := archiveText(chat, m, b.state.data.AccountID)
		if e != nil {
			return nil, e
		}
		if msg != nil {
			result = append(result, *msg)
		}
	}
	if _, e = b.authorize(r.ChatID, "read", r.JID); e != nil {
		return nil, e
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Timestamp == result[j].Timestamp {
			return result[i].ID > result[j].ID
		}
		return result[i].Timestamp > result[j].Timestamp
	})
	if len(result) > r.Limit {
		result = result[:r.Limit]
	}
	return map[string]any{"chat_id": chat.ID, "messages": result, "history": "secure_storage", "has_more": *page.Range.HasMoreBefore, "before_ms": page.Range.Before, "plaintext_saved": false}, nil
}
func decodeArchive(p *waArmadilloBackupMessage.BackupMessage) (*events.FBMessage, error) {
	payload, ok := p.GetPayload().(*waArmadilloBackupMessage.BackupMessage_EncryptedTransportMessage)
	if !ok {
		return nil, nil
	}
	var app waMsgApplication.MessageApplication
	if proto.Unmarshal(payload.EncryptedTransportMessage, &app) != nil {
		return nil, errors.New("Invalid archived application.")
	}
	evt, e := whatsmeow.DecodeFBApplication(&app)
	if e != nil {
		return nil, errors.New("Unsupported archived application.")
	}
	return &evt, nil
}
func archiveText(chat Chat, m *securehistory.DecryptedMessage, self int64) (*cachedMessage, error) {
	if chat.Disappearing {
		return nil, nil
	}
	if m == nil || m.Message == nil || m.Message.Message == nil {
		return nil, errors.New("Missing archive message metadata.")
	}
	p := m.Message.Message
	meta := p.GetMetadata()
	if meta.GetMessageID() == "" || meta.GetSenderID() == "" || m.Message.TimestampMS < 0 {
		return nil, errors.New("Invalid archive message metadata.")
	}
	evt, e := decodeArchive(p)
	if e != nil || evt == nil {
		return nil, e
	}
	if evt.FBApplication.GetMetadata().GetEphemeral() != nil {
		return nil, nil
	}
	content := evt.GetConsumerApplication().GetPayload().GetContent()
	text := content.GetMessageText()
	if text == nil {
		return nil, nil
	}
	body := text.GetText()
	lastEdit := int64(-1)
	for _, s := range m.Supplementals {
		if s == nil || s.Message == nil {
			return nil, errors.New("Invalid archive supplemental.")
		}
		other, e := decodeArchive(s.Message)
		if e != nil {
			return nil, e
		}
		if other == nil {
			continue
		}
		if revoke := other.GetConsumerApplication().GetPayload().GetApplicationData().GetRevoke(); revoke != nil && revoke.GetKey().GetID() == meta.GetMessageID() {
			return nil, nil
		}
		edit := other.GetConsumerApplication().GetPayload().GetContent().GetEditMessage()
		if edit != nil {
			if edit.GetMessage() == nil {
				return nil, errors.New("Archive edit has no text.")
			}
			if edit.GetKey().GetID() != "" && edit.GetKey().GetID() != meta.GetMessageID() || s.Message.GetMetadata().GetSenderID() != meta.GetSenderID() {
				return nil, errors.New("Archive edit target or sender mismatch.")
			}
			if s.TimestampMS > lastEdit {
				body = edit.GetMessage().GetText()
				lastEdit = s.TimestampMS
			}
		}
	}
	if len(body) > 16*1024 {
		return nil, nil
	}
	return &cachedMessage{ID: meta.GetMessageID(), ChatID: chat.ID, Sender: meta.GetSenderID(), FromMe: meta.GetSenderID() == strconv.FormatInt(self, 10), Text: body, Timestamp: m.Message.TimestampMS, Source: "secure_storage"}, nil
}
