// SPDX-License-Identifier: AGPL-3.0-or-later
package messengercli

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"go.mau.fi/util/shlex"
)

const maxCookieBytes = 256 * 1024

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("input could not be read or exceeds the size limit")
	}
	return b, nil
}

// Parses data only. In particular, copied curl commands are NEVER executed.
func parseCookies(input []byte) (map[string]string, error) {
	raw := strings.TrimSpace(string(input))
	values := map[string]string{}
	if strings.HasPrefix(raw, "{") {
		if json.Unmarshal([]byte(raw), &values) != nil {
			return nil, errors.New("cookie JSON must be an object of string values")
		}
	} else {
		if strings.HasPrefix(raw, "curl ") {
			args, err := shlex.Split(raw)
			if err != nil {
				return nil, errors.New("cannot parse copied curl request")
			}
			raw = ""
			for i := 1; i < len(args); i++ {
				switch args[i] {
				case "-b", "--cookie":
					if i+1 < len(args) {
						i++
						raw = args[i]
					}
				case "-H", "--header":
					if i+1 < len(args) {
						i++
						if k, v, ok := strings.Cut(args[i], ":"); ok && strings.EqualFold(k, "cookie") {
							raw = strings.TrimSpace(v)
						}
					}
				}
			}
		} else if key, value, ok := strings.Cut(raw, ":"); ok && strings.EqualFold(key, "cookie") {
			raw = strings.TrimSpace(value)
		}
		for _, part := range strings.Split(raw, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
				values[k] = v
			}
		}
	}
	// Keep only the login cookies needed by Messenger, not unrelated browser data.
	out := map[string]string{}
	for _, key := range []string{"c_user", "xs", "datr", "sb"} {
		value := values[key]
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("invalid control characters in cookie value")
		}
		if value != "" {
			out[key] = value
		}
	}
	id, err := strconv.ParseInt(out["c_user"], 10, 64)
	if err != nil || id <= 0 || out["xs"] == "" || out["datr"] == "" {
		return nil, errors.New("input must contain valid c_user, xs and datr login cookies; do not paste secrets into chat")
	}
	return out, nil
}

func cookieFile(path string) ([]byte, error) {
	if err := privatePath(path, false); err != nil {
		return nil, errors.New("cookie input must be an owner-only regular file (chmod 600), not a symlink")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read cookie file")
	}
	defer f.Close()
	return readBounded(f, maxCookieBytes)
}
