// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"go.mau.fi/mautrix-meta/pkg/messagix/table"
)

func TestCookieImportIsDataNotCode(t *testing.T) {
	for _, input := range []string{
		`{"c_user":"123","xs":"session:a=b","datr":"device","unrelated":"discard"}`,
		`Cookie: c_user=123; xs=session:a=b; datr=device; unrelated=discard`,
		`curl 'https://www.facebook.com/api/graphql/' -b 'c_user=123; xs=session:a=b; datr=device' -H 'x-irrelevant: $(touch /should-not-exist)'`,
		`curl 'https://www.facebook.com/' -H 'Cookie: c_user=123; xs=session:a=b; datr=device'`,
		"curl --url 'https://www.facebook.com/api/graphql/' \\\n -H 'accept: */*' \\\n -b 'c_user=123; xs=session:a=b; datr=device'",
	} {
		got, err := parseCookies([]byte(input))
		if err != nil || got["xs"] != "session:a=b" || got["c_user"] != "123" || len(got) != 3 {
			t.Fatalf("unexpected parsed cookie fields or error: %v", err)
		}
	}
	for _, input := range []string{
		`{"c_user":"123","xs":"s"}`,
		`{"c_user":"123","xs":"s\r\nInjected: header","datr":"d"}`,
		`{"c_user":"not-a-number","xs":"s","datr":"d"}`,
		`{"c_user":123,"xs":"s","datr":"d"}`,
		`curl 'https://www.facebook.com' --data 'password=DO_NOT_LOG_THIS'`,
	} {
		if _, err := parseCookies([]byte(input)); err == nil || strings.Contains(err.Error(), "DO_NOT_LOG_THIS") {
			t.Fatal("invalid cookie input was accepted or secrets appeared in an error")
		}
	}
}

func TestStatePermissionsAndLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profile")
	s, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = openState(dir); err == nil {
		t.Fatal("concurrent writer was accepted")
	}
	s.data.AccountID = 123
	s.data.Cookies = map[string]string{"xs": "fake-secret"}
	if err = s.save(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for path, mode := range map[string]os.FileMode{dir: 0700, filepath.Join(dir, "account.json"): 0600, filepath.Join(dir, ".lock"): 0600} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != mode {
			t.Fatalf("wrong permissions on %s", path)
		}
	}
	s, err = openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.data.AccountID != 123 {
		t.Fatal("profile did not survive reopening")
	}
	s.Close()
	if err = os.Chmod(filepath.Join(dir, "account.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = openState(dir); err == nil {
		t.Fatal("world-readable credential file was accepted")
	}
}

func TestStateRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, ".lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := openState(dir); err == nil {
		t.Fatal("symlink lock was accepted")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "unchanged" {
		t.Fatal("symlink target was modified")
	}
}

func seedProfile(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profile")
	s, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.data.AccountID = 123
	s.data.Platform = "facebook"
	s.ingest(&table.LSTable{
		LSDeleteThenInsertThread: []*table.LSDeleteThenInsertThread{
			{ThreadKey: 100, ThreadName: "Encrypted friend", ThreadType: table.ENCRYPTED_OVER_WA_ONE_TO_ONE},
			{ThreadKey: 200, ThreadName: "Legacy", ThreadType: table.ONE_TO_ONE},
			{ThreadKey: 300, ThreadName: "Group", ThreadType: table.ENCRYPTED_OVER_WA_GROUP},
			{ThreadKey: 400, ThreadName: "Ephemeral", ThreadType: table.ENCRYPTED_OVER_WA_ONE_TO_ONE, DisappearingSettingTtl: 60},
		},
		LSVerifyHybridThreadExists: []*table.LSVerifyHybridThreadExists{{ThreadKey: 100, ThreadJID: 999, ThreadType: table.ENCRYPTED_OVER_WA_ONE_TO_ONE}},
	})
	if err = s.save(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	return dir
}

func TestEncryptedRoutingAndDryRun(t *testing.T) {
	dir := seedProfile(t)
	s, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.resolve("100")
	if err != nil || c.JID != "999@msgr" {
		t.Fatalf("hybrid mapping incorrect: %v", err)
	}
	c, err = s.resolve("300")
	if err != nil || c.JID != "300@g.us" {
		t.Fatalf("group mapping incorrect: %v", err)
	}
	for _, id := range []string{"", "Encrypted friend", "9999", "200", "400", "+100", "100@msgr"} {
		if _, err := s.resolve(id); err == nil {
			t.Fatalf("unsafe or unknown target accepted: %q", id)
		}
	}
	s.Close()
	var out, diag bytes.Buffer
	// No cookies exist: success proves dry-run did not attempt login or registration.
	err = Run(context.Background(), []string{"--state-dir", dir, "send", "--chat", "100", "--text", "hello", "--dry-run"}, strings.NewReader(""), &out, &diag)
	if err != nil || !strings.Contains(out.String(), `"network_used":false`) || !strings.Contains(out.String(), "999@msgr") {
		t.Fatalf("offline preview failed: %v; %s", err, out.String())
	}
}

func TestRejectedSendStopsBeforeLogin(t *testing.T) {
	dir := seedProfile(t)
	for _, reply := range []string{"", "no\n", "send\n"} {
		var out, diag bytes.Buffer
		err := Run(context.Background(), []string{"--state-dir", dir, "send", "--chat", "100", "--text", "hello"}, strings.NewReader(reply), &out, &diag)
		if err == nil || !strings.Contains(err.Error(), "canceled") || out.Len() != 0 {
			t.Fatalf("send was not canceled before network: %v", err)
		}
	}
}

func TestNoSecretDiagnosticsAndAccountMixup(t *testing.T) {
	secret := "SESSION_SECRET_MUST_NOT_LEAK"
	if strings.Contains(safeNetworkError("loading inbox", fmt.Errorf("https://example.invalid/?token=%s", secret)).Error(), secret) {
		t.Fatal("network error leaked a token")
	}
	s := &stateStore{data: accountState{AccountID: 123}}
	_, err := loadSession(context.Background(), s, map[string]string{"c_user": "456", "xs": secret, "datr": "d"}, "facebook")
	if err == nil || !strings.Contains(err.Error(), "different account") || strings.Contains(err.Error(), secret) {
		t.Fatal("cross-account reuse was not blocked before network")
	}
	if !strings.Contains(safeNetworkError("connect", context.Canceled).Error(), "canceled") {
		t.Fatal("cancel classification failed")
	}
	if !strings.Contains(safeNetworkError("connect", context.DeadlineExceeded).Error(), "timed out") {
		t.Fatal("timeout classification failed")
	}
}

func TestMessageValidationAndControlCharacters(t *testing.T) {
	for _, text := range []string{"", " \n", "hello\x00world", strings.Repeat("x", 16385), string([]byte{0xff})} {
		if _, err := readMessage(strings.NewReader(text), "", "", true); err == nil {
			t.Fatal("invalid message accepted")
		}
	}
	if _, err := readMessage(strings.NewReader("ignored"), "hello", "", true); err == nil {
		t.Fatal("ambiguous input accepted")
	}
	text := "こんにちは\nsecond line\n"
	got, err := readMessage(strings.NewReader(text), "", "", true)
	if err != nil || got != text {
		t.Fatal("valid input was altered")
	}
	if strings.ContainsRune(safeDisplay("Name\x1b[2J"), '\x1b') {
		t.Fatal("terminal escape was not neutralized")
	}
	msg := textMessage(text)
	if msg.GetPayload().GetContent().GetMessageText().GetText() != text {
		t.Fatal("E2EE message content was altered")
	}
	if _, err := readBounded(strings.NewReader("1234"), 3); err == nil {
		t.Fatal("size limit not enforced")
	}
	if _, err := readBounded(errorReader{}, 3); err == nil {
		t.Fatal("read error ignored")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read error") }

func TestContactNamesSurviveSeparateSyncBatches(t *testing.T) {
	dir := seedProfile(t)
	s, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.data.Chats["100"] = Chat{ID: "100", Type: table.ENCRYPTED_OVER_WA_ONE_TO_ONE}
	s.ingest(&table.LSTable{
		LSDeleteThenInsertContact: []*table.LSDeleteThenInsertContact{{Id: 999, Name: "Mapped friend"}},
	})
	chat, err := s.resolve("100")
	if err != nil || chat.Name != "Mapped friend" || chat.JID != "999@msgr" {
		t.Fatalf("contact name was not applied across batches: %v", err)
	}
}

type globalLogProbe struct{ io.Writer }

func (w globalLogProbe) Write(b []byte) (int, error) {
	// Simulate the decoder's use of the package-global logger, which bypasses
	// the per-client logger. The CLI must suppress this as well.
	log.Warn().Str("private_payload", "FAKE_SESSION_SECRET").Msg("decoder warning")
	return w.Writer.Write(b)
}

func TestCLIAlsoDisablesGlobalProtocolLogs(t *testing.T) {
	previousLogger, previousLevel := log.Logger, zerolog.GlobalLevel()
	defer func() { log.Logger = previousLogger; zerolog.SetGlobalLevel(previousLevel) }()
	var leaked, out, diagnostic bytes.Buffer
	log.Logger = zerolog.New(&leaked)
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	err := Run(context.Background(), []string{"--help"}, strings.NewReader(""), globalLogProbe{&out}, &diagnostic)
	if err != nil || leaked.Len() != 0 || out.Len() == 0 {
		t.Fatalf("global protocol logs were not suppressed: %v", err)
	}
	if zerolog.GlobalLevel() != zerolog.TraceLevel {
		t.Fatal("caller logging level was not restored")
	}
}
