// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waConsumerApplication"
	"go.mau.fi/whatsmeow/store/sqlstore"
	watypes "go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-meta/pkg/messagix"
	"go.mau.fi/mautrix-meta/pkg/messagix/cookies"
	"go.mau.fi/mautrix-meta/pkg/messagix/methods"
	"go.mau.fi/mautrix-meta/pkg/messagix/socket"
	"go.mau.fi/mautrix-meta/pkg/messagix/table"
	"go.mau.fi/mautrix-meta/pkg/messagix/types"
)

type session struct {
	web        *messagix.Client
	e2ee       *whatsmeow.Client
	db         *sqlstore.Container
	state      *stateStore
	ready      chan struct{}
	fatal      chan error
	once       sync.Once
	dirty      chan struct{}
	onMessage  func(*events.FBMessage) bool
	keepOnline bool
}

func platform(name string) (types.Platform, error) {
	switch name {
	case "facebook":
		return types.Facebook, nil
	case "messenger":
		return types.Messenger, nil
	default:
		return types.Unset, errors.New("platform must be facebook or messenger")
	}
}

func safeNetworkError(stage string, err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.New(stage + ": canceled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New(stage + ": timed out")
	}
	// Upstream errors sometimes contain full URLs, tokens or response bodies.
	// Never interpolate err here, even at a verbose logging level.
	return errors.New(stage + ": failed; check the official Messenger website for login or account verification, then import fresh cookies if needed")
}

func loadSession(ctx context.Context, s *stateStore, cs map[string]string, mode string) (*session, error) {
	p, err := platform(mode)
	if err != nil {
		return nil, err
	}
	c := &cookies.Cookies{Platform: p}
	values := make(map[cookies.MetaCookieName]string)
	for k, v := range cs {
		values[cookies.MetaCookieName(k)] = v
	}
	c.UpdateValues(values)
	if len(c.GetMissingCookieNames()) != 0 {
		return nil, errors.New("login cookies are missing; run 'messenger login'")
	}
	if s.data.AccountID != 0 && c.GetUserID() != s.data.AccountID {
		return nil, errors.New("these cookies belong to a different account; use another --state-dir")
	}
	cli := &session{
		state: s, ready: make(chan struct{}), fatal: make(chan error, 1), dirty: make(chan struct{}, 1),
	}
	// No raw upstream logs: even warning/error payloads can contain secrets.
	cli.web = messagix.NewClient(c, zerolog.Nop(), &messagix.Config{ClientSettings: exhttp.SensibleClientSettings})
	cli.web.SetEventHandler(cli.event)
	user, tbl, err := cli.web.LoadMessagesPage(ctx)
	if err != nil {
		return nil, safeNetworkError("loading inbox", err)
	}
	if user == nil || user.GetFBID() <= 0 || user.GetFBID() != c.GetUserID() {
		return nil, errors.New("Messenger returned an unexpected account; profile was not changed")
	}
	s.data.AccountID, s.data.Name, s.data.Platform = user.GetFBID(), user.GetName(), mode
	s.ingest(tbl)
	if err = s.saveCookies(c); err != nil {
		return nil, err
	}
	return cli, nil
}

func (c *session) event(ctx context.Context, evt any) {
	switch e := evt.(type) {
	case *table.LSTable:
		c.state.ingest(e)
		c.web.PostHandlePublishResponse(e)
		select {
		case c.dirty <- struct{}{}:
		default:
		}
	case *messagix.ConnectedEvent:
		c.once.Do(func() { close(c.ready) })
	case *messagix.PermanentErrorEvent:
		select {
		case c.fatal <- errors.New("Messenger session rejected; import fresh cookies"):
		default:
		}
	}
}

func (c *session) connectWeb(ctx context.Context) error {
	if err := c.web.Connect(ctx); err != nil {
		return safeNetworkError("connecting inbox", err)
	}
	select {
	case <-c.ready:
		return nil
	case err := <-c.fatal:
		return err
	case <-ctx.Done():
		return safeNetworkError("syncing inbox", ctx.Err())
	}
}

func (c *session) syncChats(ctx context.Context, pages int) error {
	if err := c.connectWeb(ctx); err != nil {
		return err
	}
	for _, group := range []int64{1, 95} {
		for i := 0; i < pages; i++ {
			cursor, tbl, err := c.web.FetchMoreThreads(ctx, group)
			if err != nil {
				return safeNetworkError("fetching chats", err)
			}
			c.state.ingest(tbl)
			if cursor == nil || !cursor.HasMoreBefore {
				break
			}
		}
	}
	// E2EE DM rows often omit their display names. Resolve only IDs already
	// present in this inbox, rather than importing the entire contact directory.
	resolved := 0
	for _, chat := range c.state.listChats() {
		if chat.Name != "" || chat.Type != table.ENCRYPTED_OVER_WA_ONE_TO_ONE || resolved >= 25 {
			continue
		}
		jid, parseErr := watypes.ParseJID(chat.JID)
		id, parseIDErr := strconv.ParseInt(jid.User, 10, 64)
		if parseErr != nil || parseIDErr != nil || id <= 0 {
			continue
		}
		resolved++
		tbl, fetchErr := c.web.ExecuteTasks(ctx, &socket.GetContactsFullTask{ContactID: id})
		if fetchErr != nil {
			return safeNetworkError("resolving chat names", fetchErr)
		}
		c.state.ingest(tbl)
	}
	return c.state.saveCookies(c.web.GetCookies())
}

func (c *session) connectE2EE(ctx context.Context, allowRegister bool) error {
	dbPath := filepath.Join(c.state.dir, "device.db")
	if err := privatePath(dbPath, false); errors.Is(err, os.ErrNotExist) {
		if !allowRegister {
			return errors.New("no saved E2EE device; run 'messenger login' to register this CLI")
		}
		f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return errors.New("cannot create private device database")
		}
		f.Close()
	} else if err != nil {
		return err
	}
	uri := (&url.URL{Scheme: "file", Path: dbPath}).String() + "?_foreign_keys=on&_busy_timeout=5000&_journal_mode=DELETE"
	db, err := sql.Open("sqlite3", uri)
	if err != nil {
		return errors.New("cannot open device database")
	}
	db.SetMaxOpenConns(1)
	c.db = sqlstore.NewWithDB(db, "sqlite3", nil)
	if err = c.db.Upgrade(ctx); err != nil {
		return errors.New("cannot initialize device database")
	}
	devices, err := c.db.GetAllDevices(ctx)
	if err != nil {
		return errors.New("cannot load saved E2EE device")
	}
	device := c.db.NewDevice()
	if len(devices) > 1 {
		return errors.New("profile contains multiple devices; refusing to select one implicitly")
	} else if len(devices) == 1 {
		device = devices[0]
		if device.ID == nil || device.ID.User != strconv.FormatInt(c.state.data.AccountID, 10) || device.ID.Server != watypes.MessengerServer {
			return errors.New("saved E2EE device belongs to a different account")
		}
	}
	c.web.SetDevice(device)
	if device.ID == nil {
		if !allowRegister {
			return errors.New("no registered E2EE device; run 'messenger login'")
		}
		if err = c.web.RegisterE2EE(ctx, c.state.data.AccountID); err != nil {
			return safeNetworkError("registering E2EE device", err)
		}
		if err = device.Save(ctx); err != nil {
			return errors.New("E2EE registration succeeded, but saving device keys failed; do not blindly repeat login")
		}
	}
	c.state.data.DeviceJID = device.ID.String()
	if err = c.state.save(); err != nil {
		return err
	}
	c.e2ee, err = c.web.PrepareE2EEClient()
	if err != nil {
		return safeNetworkError("preparing E2EE", err)
	}
	connected := make(chan struct{})
	failure := make(chan struct{}, 1)
	var once sync.Once
	c.e2ee.EnableAutoReconnect = c.keepOnline
	c.e2ee.InitialAutoReconnect = false
	c.e2ee.SynchronousAck = true
	c.e2ee.EnableDecryptedEventBuffer = false
	c.e2ee.AddEventHandlerWithSuccessStatus(func(evt any) bool {
		switch evt.(type) {
		case *events.FBMessage:
			if c.onMessage != nil {
				return c.onMessage(evt.(*events.FBMessage))
			}
		case *events.Connected:
			once.Do(func() { close(connected) })
		case *events.ConnectFailure, *events.LoggedOut:
			select {
			case failure <- struct{}{}:
			default:
			}
		}
		return true
	})
	if err = c.e2ee.ConnectContext(ctx); err != nil {
		return safeNetworkError("connecting E2EE", err)
	}
	select {
	case <-connected:
		return nil
	case <-failure:
		return errors.New("Messenger rejected this E2EE device; check your account before retrying")
	case <-ctx.Done():
		return safeNetworkError("waiting for E2EE", ctx.Err())
	case <-time.After(60 * time.Second):
		return errors.New("waiting for E2EE: timed out")
	}
}

type sendResult struct {
	Status    string    `json:"status"`
	ChatID    string    `json:"chat_id"`
	MessageID string    `json:"message_id"`
	Timestamp time.Time `json:"timestamp"`
}

func textMessage(text string) *waConsumerApplication.ConsumerApplication {
	return &waConsumerApplication.ConsumerApplication{
		Payload: &waConsumerApplication.ConsumerApplication_Payload{
			Payload: &waConsumerApplication.ConsumerApplication_Payload_Content{
				Content: &waConsumerApplication.ConsumerApplication_Content{
					Content: &waConsumerApplication.ConsumerApplication_Content_MessageText{
						MessageText: &waCommon.MessageText{Text: proto.String(text)},
					},
				},
			},
		},
	}
}

func (c *session) send(ctx context.Context, chat Chat, text string) (*sendResult, error) {
	jid, err := watypes.ParseJID(chat.JID)
	if err != nil || jid.User == "" || (jid.Server != watypes.MessengerServer && jid.Server != watypes.GroupServer) {
		return nil, errors.New("invalid encrypted chat address; refresh chats first")
	}
	messageID := strconv.FormatInt(methods.GenerateEpochID(), 10)
	resp, err := c.e2ee.SendFBMessage(ctx, jid, textMessage(text), nil, whatsmeow.SendRequestExtra{ID: messageID})
	if err != nil {
		return nil, fmt.Errorf("send outcome unknown for message ID %s; check Messenger before retrying (no automatic resend)", messageID)
	}
	return &sendResult{Status: "server_acknowledged", ChatID: chat.ID, MessageID: resp.ID, Timestamp: resp.Timestamp}, nil
}

func (c *session) close() error {
	if c.e2ee != nil {
		c.e2ee.Disconnect()
	}
	if c.web != nil {
		c.web.Disconnect()
	}
	var dbErr error
	if c.db != nil {
		dbErr = c.db.Close()
	}
	err := c.state.saveCookies(c.web.GetCookies())
	if err != nil || dbErr != nil {
		return errors.New("failed to persist session state; verify Messenger before any retry")
	}
	return nil
}
