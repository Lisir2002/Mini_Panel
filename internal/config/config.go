// Package config loads the panel's bootstrap configuration.
//
// Split of truth, deliberately: the JSON file owns the values you need *before*
// the database is reachable (port, bind address, entrance path, TLS, paths), and
// SQLite owns everything mutable at runtime. Other panels split the same values
// across one file per setting; this keeps them in one place with real types and
// no "empty file means enabled" ambiguity.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Bind         string   `json:"bind"`     // 0.0.0.0 | 127.0.0.1 | specific IP
	Port         int      `json:"port"`     // panel port (BaoTa: a random high port)
	Entrance     string   `json:"entrance"` // security entrance path, e.g. /k7m2q9x4
	TLS          bool     `json:"tls"`      // serve HTTPS (refuses login when false)
	Hosts        []string `json:"hosts"`    // SANs for the self-signed panel cert
	DataDir      string   `json:"data_dir"` // db + tls + runtime files
	LogDir       string   `json:"log_dir"`
	SessionTTL   Duration `json:"session_ttl"`   // default 12h, shorter than BaoTa's 24h
	LoginLimit   int      `json:"login_limit"`   // failures per IP before lockout (BaoTa: 5)
	UnauthStatus int      `json:"unauth_status"` // status code for wrong entrance/no session
}

// Duration accepts either a Go duration string ("12h") or nanoseconds, so a
// hand-edited panel.json never silently becomes 12 nanoseconds.
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		*d = Duration(n)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("bad duration %q", s)
	}
	*d = Duration(v)
	return nil
}

const FileName = "panel.json"

func Default() *Config {
	return &Config{
		Bind:         "0.0.0.0",
		Port:         29080,
		Entrance:     "",
		TLS:          true,
		SessionTTL:   Duration(12 * time.Hour),
		LoginLimit:   5,
		UnauthStatus: 404,
	}
}

// Path returns the config file location inside dir.
func Path(dir string) string { return filepath.Join(dir, FileName) }

func Load(dir string) (*Config, error) {
	c := Default()
	b, err := os.ReadFile(Path(dir))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", Path(dir), err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := Path(dir) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, Path(dir))
}

func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("panel.port out of range: %d", c.Port)
	}
	if c.Bind == "" {
		return errors.New("panel.bind must not be empty")
	}
	if c.SessionTTL.D() < time.Minute {
		c.SessionTTL = Duration(12 * time.Hour)
	}
	if c.LoginLimit <= 0 {
		c.LoginLimit = 5
	}
	switch c.UnauthStatus {
	case 400, 401, 403, 404, 444:
	default:
		return fmt.Errorf("unauth_status must be one of 400/401/403/404/444, got %d", c.UnauthStatus)
	}
	if c.DataDir == "" {
		return errors.New("panel.data_dir must not be empty")
	}
	return nil
}

// Addr is the listen address for net.Listen / http.Server.
func (c *Config) Addr() string { return fmt.Sprintf("%s:%d", c.Bind, c.Port) }
