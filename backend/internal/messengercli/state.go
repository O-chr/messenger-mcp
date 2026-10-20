// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"go.mau.fi/mautrix-meta/pkg/messagix/cookies"
	"go.mau.fi/mautrix-meta/pkg/messagix/securehistory"
	"go.mau.fi/mautrix-meta/pkg/messagix/table"
)

type Chat struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Type         table.ThreadType `json:"type"`
	JID          string           `json:"jid,omitempty"`
	Activity     int64            `json:"last_activity_ms,omitempty"`
	Disappearing bool             `json:"disappearing,omitempty"`
}

type accountState struct {
	Version       int                   `json:"version"`
	AccountID     int64                 `json:"account_id"`
	Name          string                `json:"name"`
	Platform      string                `json:"platform"`
	Cookies       map[string]string     `json:"cookies"`
	Chats         map[string]Chat       `json:"chats"`
	Mappings      map[string]string     `json:"mappings"`
	Names         map[string]string     `json:"contact_names,omitempty"`
	DeviceJID     string                `json:"device_jid,omitempty"`
	HistoryDevice *securehistory.Device `json:"history_device,omitempty"`
}

type stateStore struct {
	dir  string
	lock *os.File
	mu   sync.Mutex
	data accountState
}

func defaultStateDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", errors.New("cannot find your configuration directory; use --state-dir")
	}
	return filepath.Join(base, "messenger-cli"), nil
}

// Private files must not be symlinks or readable by another OS account.
func privatePath(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (dir && !info.IsDir()) || (!dir && !info.Mode().IsRegular()) {
		return errors.New("state path must be a real directory or regular file, not a symlink")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("state permissions are too broad; use 700 for the directory and 600 for files")
	}
	return nil
}

func openState(dir string) (*stateStore, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, errors.New("invalid state directory")
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return nil, errors.New("cannot create the private state directory")
	}
	if err = privatePath(abs, true); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(abs, ".lock")
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("cannot open state lock")
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	if err = privatePath(lockPath, false); err != nil {
		lock.Close()
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("another Messenger CLI process is using this profile")
	}
	s := &stateStore{dir: abs, lock: lock}
	s.data.Version = 1
	s.data.Chats = make(map[string]Chat)
	s.data.Mappings = make(map[string]string)
	s.data.Names = make(map[string]string)
	p := filepath.Join(abs, "account.json")
	if err = privatePath(p, false); errors.Is(err, os.ErrNotExist) {
		return s, nil
	} else if err != nil {
		s.Close()
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil || json.Unmarshal(b, &s.data) != nil || s.data.Version != 1 {
		s.Close()
		return nil, errors.New("cannot read this profile; the account file is invalid or unsupported")
	}
	if s.data.Chats == nil {
		s.data.Chats = make(map[string]Chat)
	}
	if s.data.Mappings == nil {
		s.data.Mappings = make(map[string]string)
	}
	if s.data.Names == nil {
		s.data.Names = make(map[string]string)
	}
	return s, nil
}

func (s *stateStore) Close() {
	if s.lock != nil {
		_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
		_ = s.lock.Close()
		s.lock = nil
	}
}

func (s *stateStore) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return errors.New("cannot encode profile")
	}
	f, err := os.CreateTemp(s.dir, ".account-*")
	if err != nil {
		return errors.New("cannot write profile")
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot save profile")
	}
	if err = os.Rename(f.Name(), filepath.Join(s.dir, "account.json")); err != nil {
		return errors.New("cannot replace profile")
	}
	return nil
}

func (s *stateStore) saveCookies(c *cookies.Cookies) error {
	s.mu.Lock()
	s.data.Cookies = make(map[string]string)
	for k, v := range c.GetAll() {
		s.data.Cookies[string(k)] = v
	}
	s.mu.Unlock()
	return s.save()
}

func (s *stateStore) listChats() []Chat {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Chat, 0, len(s.data.Chats))
	for _, c := range s.data.Chats {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Activity != out[j].Activity {
			return out[i].Activity > out[j].Activity
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *stateStore) ingest(tbl *table.LSTable) {
	if tbl == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range tbl.LSUpdateThreadAuthorityAndMappingWithOTIDFromJID {
		s.data.Mappings[fmt.Sprint(m.ThreadKey)] = fmt.Sprint(m.ThreadJID)
	}
	for _, m := range tbl.LSVerifyHybridThreadExists {
		s.data.Mappings[fmt.Sprint(m.ThreadKey)] = fmt.Sprint(m.ThreadJID)
	}
	upsert := func(id int64, name string, typ table.ThreadType, activity int64) {
		if id <= 0 {
			return
		}
		key := fmt.Sprint(id)
		c := s.data.Chats[key]
		c.ID = key
		if name != "" {
			c.Name = name
		}
		if typ != 0 {
			c.Type = typ
		}
		if activity != 0 {
			c.Activity = activity
		}
		s.data.Chats[key] = c
	}
	for _, t := range tbl.LSDeleteThenInsertThread {
		if t.ThreadKey <= 0 {
			continue
		}
		upsert(t.ThreadKey, t.ThreadName, t.ThreadType, t.LastActivityTimestampMs)
		c := s.data.Chats[fmt.Sprint(t.ThreadKey)]
		c.Disappearing = t.DisappearingSettingTtl > 0 || t.IsDisappearingMode
		s.data.Chats[c.ID] = c
	}
	for _, t := range tbl.LSUpdateOrInsertThread {
		if t.ThreadKey <= 0 {
			continue
		}
		upsert(t.ThreadKey, t.ThreadName, t.ThreadType, t.LastActivityTimestampMs)
		c := s.data.Chats[fmt.Sprint(t.ThreadKey)]
		c.Disappearing = t.DisappearingSettingTtl > 0 || t.IsDisappearingMode
		s.data.Chats[c.ID] = c
	}
	for _, t := range tbl.LSVerifyThreadExists {
		upsert(t.ThreadKey, "", t.ThreadType, 0)
	}
	for _, t := range tbl.LSVerifyHybridThreadExists {
		upsert(t.ThreadKey, "", t.ThreadType, 0)
	}
	// Fill DM names from contact rows, without keeping phone/email/message bodies.
	for _, c := range tbl.LSDeleteThenInsertContact {
		id := fmt.Sprint(c.Id)
		if c.Name != "" {
			s.data.Names[id] = c.Name
		}
		if t, ok := s.data.Chats[id]; ok && t.Type.IsOneToOne() && t.Name == "" {
			t.Name = c.Name
			s.data.Chats[id] = t
		}
	}
	for _, c := range tbl.LSVerifyContactRowExists {
		id := fmt.Sprint(c.ContactId)
		if c.Name != "" {
			s.data.Names[id] = c.Name
		}
		if t, ok := s.data.Chats[id]; ok && t.Type.IsOneToOne() && t.Name == "" {
			t.Name = c.Name
			s.data.Chats[id] = t
		}
	}
	for id, c := range s.data.Chats {
		if !c.Type.IsWhatsApp() {
			continue
		}
		mapped := s.data.Mappings[id]
		if mapped == "" {
			mapped = id
		}
		if c.Name == "" && c.Type.IsOneToOne() {
			c.Name = s.data.Names[mapped]
			if c.Name == "" {
				c.Name = s.data.Names[id]
			}
		}
		server := "msgr"
		if c.Type == table.ENCRYPTED_OVER_WA_GROUP {
			server = "g.us"
		}
		c.JID = mapped + "@" + server
		s.data.Chats[id] = c
	}
	for _, t := range tbl.LSDeleteThread {
		delete(s.data.Chats, fmt.Sprint(t.ThreadKey))
	}
}

func (s *stateStore) resolve(id string) (Chat, error) {
	if id == "" || strings.Trim(id, "0123456789") != "" {
		return Chat{}, errors.New("use the exact numeric chat ID shown by 'messenger chats'")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.data.Chats[id]
	if !ok {
		return Chat{}, errors.New("unknown chat ID; refresh 'messenger chats' first")
	}
	if !c.Type.IsWhatsApp() || c.JID == "" {
		return Chat{}, errors.New("this chat is not a supported E2EE chat; plaintext sending is disabled")
	}
	if c.Disappearing {
		return Chat{}, errors.New("disappearing-message chats are not supported by this first CLI version")
	}
	return c, nil
}
