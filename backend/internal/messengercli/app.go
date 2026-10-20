// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rs/zerolog"
	"golang.org/x/term"
)

const help = `Messenger CLI (experimental, local profile)

Usage: messenger [--state-dir PATH] COMMAND [OPTIONS]

Commands:
  login   [--platform facebook|messenger] [--stdin | --cookie-file PATH]
          Import cookies, verify the account, and register/connect an E2EE device.
          Interactive input is hidden; copied curl requests are parsed, never run.
  status  Show local profile status without connecting to Meta.
  chats   [--cached] [--pages N] [--json]
          List recently synced chats. --pages adds up to N older pages per group.
  send    --chat ID (--text TEXT | --text-file PATH | --stdin) [--yes] [--dry-run]
          Send E2EE text to an exact cached chat ID. Confirmation is required
          unless --yes is explicitly supplied. --dry-run never connects or sends.

Each online command accepts --timeout (default 90s). No raw protocol logs.
Cookie/key files are private (700 directory, 600 files), not encrypted by this
CLI. Keep the profile on an encrypted local disk and out of cloud sync.
Server acknowledgement means accepted by the server, not delivered or read.
`

func Run(ctx context.Context, args []string, in io.Reader, out, diagnostic io.Writer) (err error) {
	// LightSpeed's decoder also uses zerolog's package-global logger, rather than
	// the supplied per-client logger. Disable both paths before touching input.
	previousLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(previousLevel)
	root := flag.NewFlagSet("messenger", flag.ContinueOnError)
	root.SetOutput(diagnostic)
	dir := root.String("state-dir", "", "private local profile directory")
	root.Usage = func() { fmt.Fprint(out, help) }
	if err = root.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return errors.New("invalid global options; use messenger --help")
	}
	args = root.Args()
	if len(args) == 0 || args[0] == "help" {
		fmt.Fprint(out, help)
		return nil
	}
	command := args[0]
	if command == "bridge" {
		return runBridge(ctx, args[1:], *dir, in, out)
	}
	if command != "login" && command != "status" && command != "chats" && command != "send" {
		return errors.New("unknown command; use messenger --help")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(diagnostic)
	timeout := fs.Duration("timeout", 90*time.Second, "network timeout")
	var mode, inputPath, chatID, text, textPath *string
	var stdin, cached, asJSON, yes, dryRun *bool
	var pages *int
	switch command {
	case "login":
		mode = fs.String("platform", "facebook", "cookie origin: facebook or messenger")
		inputPath = fs.String("cookie-file", "", "owner-only JSON, Cookie header or copied curl file")
		stdin = fs.Bool("stdin", false, "read cookies from stdin")
	case "chats":
		cached = fs.Bool("cached", false, "use saved metadata, no network")
		asJSON = fs.Bool("json", false, "JSON output")
		pages = fs.Int("pages", 0, "additional pages per sync group (0-10)")
	case "send":
		chatID = fs.String("chat", "", "exact numeric chat ID")
		text = fs.String("text", "", "message text (visible in shell history/process list)")
		textPath = fs.String("text-file", "", "UTF-8 message file")
		stdin = fs.Bool("stdin", false, "read message from stdin")
		yes = fs.Bool("yes", false, "explicitly authorize this send without interactive confirmation")
		dryRun = fs.Bool("dry-run", false, "preview cached target, do not connect or send")
	}
	if err = fs.Parse(args[1:]); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil || len(fs.Args()) != 0 {
		return errors.New("invalid command options; put flags before positional arguments")
	}
	if *timeout < time.Second || *timeout > 10*time.Minute {
		return errors.New("timeout must be between 1s and 10m")
	}
	if *dir == "" {
		*dir, err = defaultStateDir()
		if err != nil {
			return err
		}
	}
	s, err := openState(*dir)
	if err != nil {
		return err
	}
	defer s.Close()
	logger := zerolog.Nop()
	ctx, cancel := context.WithTimeout(logger.WithContext(ctx), *timeout)
	defer cancel()
	if command == "status" {
		return json.NewEncoder(out).Encode(map[string]any{
			"profile_exists": s.data.AccountID != 0,
			"account_id":     fmt.Sprint(s.data.AccountID), "name": s.data.Name,
			"platform": s.data.Platform, "device_registered": s.data.DeviceJID != "",
			"cached_chats": len(s.data.Chats), "network_checked": false,
		})
	}
	if command == "chats" && *cached {
		return outputChats(s, *asJSON, out)
	}
	var message string
	var target Chat
	if command == "send" {
		message, err = readMessage(in, *text, *textPath, *stdin)
		if err != nil {
			return err
		}
		target, err = s.resolve(*chatID)
		if err != nil {
			return err
		}
		if *dryRun {
			return json.NewEncoder(out).Encode(map[string]any{
				"dry_run": true, "chat": target, "text": message, "network_used": false,
			})
		}
		if !*yes {
			if *stdin {
				return errors.New("stdin message input requires --yes; preview with --dry-run first")
			}
			fmt.Fprintf(diagnostic, "Send to %s (chat %s)?\n%s\nType SEND to confirm: ", safeDisplay(target.Name), target.ID, safeDisplay(message))
			line, readErr := bufio.NewReader(in).ReadString('\n')
			if readErr != nil || strings.TrimSpace(line) != "SEND" {
				return errors.New("send canceled; nothing was sent")
			}
		}
	}
	cs, selectedMode := s.data.Cookies, s.data.Platform
	if command == "login" {
		if _, err = platform(*mode); err != nil {
			return err
		}
		if *stdin && *inputPath != "" {
			return errors.New("choose either --stdin or --cookie-file")
		}
		var b []byte
		switch {
		case *stdin:
			b, err = readBounded(in, maxCookieBytes)
		case *inputPath != "":
			b, err = cookieFile(*inputPath)
		default:
			f, ok := in.(*os.File)
			if !ok || !term.IsTerminal(int(f.Fd())) {
				return errors.New("use --stdin or --cookie-file for non-interactive login")
			}
			fmt.Fprint(diagnostic, "Paste Cookie header or cookie JSON (hidden), then Enter: ")
			b, err = term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(diagnostic)
		}
		if err != nil {
			return errors.New("could not read cookie input")
		}
		if len(b) > maxCookieBytes {
			return errors.New("cookie input exceeds size limit")
		}
		cs, err = parseCookies(b)
		clear(b)
		if err != nil {
			return err
		}
		selectedMode = *mode
	} else if s.data.AccountID == 0 {
		return errors.New("no profile; run 'messenger login' first")
	}
	if command == "chats" && (*pages < 0 || *pages > 10) {
		return errors.New("pages must be between 0 and 10")
	}
	cli, err := loadSession(ctx, s, cs, selectedMode)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := cli.close(); err == nil {
			err = closeErr
		}
	}()
	switch command {
	case "login":
		fmt.Fprintln(diagnostic, "Account verified. Connecting this CLI as an E2EE device...")
		if err = cli.connectE2EE(ctx, true); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{
			"status": "connected", "account_id": fmt.Sprint(s.data.AccountID),
			"name": s.data.Name, "device_registered": true,
		})
	case "chats":
		if err = cli.syncChats(ctx, *pages); err != nil {
			return err
		}
		return outputChats(s, *asJSON, out)
	case "send":
		// Refresh target metadata before sending, but never silently change its address.
		current, resolveErr := s.resolve(*chatID)
		if resolveErr != nil || current.JID != target.JID || current.Type != target.Type {
			return errors.New("chat encryption/address changed; refresh chats and review the target again")
		}
		if err = cli.connectE2EE(ctx, false); err != nil {
			return err
		}
		result, sendErr := cli.send(ctx, target, message)
		if sendErr != nil {
			return sendErr
		}
		return json.NewEncoder(out).Encode(result)
	}
	return nil
}

func readMessage(in io.Reader, text, path string, stdin bool) (string, error) {
	count := 0
	for _, enabled := range []bool{text != "", path != "", stdin} {
		if enabled {
			count++
		}
	}
	if count != 1 {
		return "", errors.New("choose exactly one of --text, --text-file or --stdin")
	}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return "", errors.New("cannot open message file")
		}
		defer f.Close()
		in = f
	}
	if path != "" || stdin {
		b, err := readBounded(in, 16*1024)
		if err != nil {
			return "", err
		}
		text = string(b)
	}
	if !utf8.ValidString(text) || strings.TrimSpace(text) == "" || len(text) > 16*1024 || strings.ContainsRune(text, 0) {
		return "", errors.New("message must be non-empty UTF-8 text up to 16 KiB, without NUL characters")
	}
	return text, nil
}

func safeDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return '\uFFFD'
		}
		return r
	}, s)
}

func outputChats(s *stateStore, asJSON bool, out io.Writer) error {
	chats := s.listChats()
	if asJSON {
		return json.NewEncoder(out).Encode(chats)
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CHAT ID\tE2EE\tNAME")
	for _, c := range chats {
		fmt.Fprintf(w, "%s\t%t\t%s\n", c.ID, c.Type.IsWhatsApp(), strings.ReplaceAll(safeDisplay(c.Name), "\n", " "))
	}
	return w.Flush()
}
