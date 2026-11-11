package nginx

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Basic authentication is a fixed HTTP Basic Auth gate on the whole vhost. The
// panel owns the password file (the only place a credential-derived value is
// stored), the realm and the directive shape; the operator supplies a username
// and a password, never a config fragment. Coexisting with every other site
// feature is deliberate: auth_basic is a server-level directive, it does not
// claim `location /` and it does not change where a request is routed.

const (
	// authRealm is what the browser shows in its credential prompt. It is a
	// constant because it is written into nginx config unquoted-by-caller.
	authRealm = "Mini Panel"
	// authFileSuffix keeps panel password files distinguishable from a
	// hand-made htpasswd in the same directory.
	authFileSuffix = ".htpasswd"
)

// authUserRe is also the marker validator: a username that cannot be written
// safely must make the file foreign instead of being rendered.
var authUserRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// authPath is the one place the password-file location is derived. It lives in
// its own directory (not next to the vhost) so the file can stay 0600 while the
// vhost remains 0644, and so a vhost glob cannot pick it up as a config.
func authPath(authDir, name string) string {
	return filepath.Join(authDir, filePrefix+name+authFileSuffix)
}

// authHash produces the `{SHA}` form nginx accepts in auth_basic_user_file:
// base64(SHA-1(password)). It is deliberately unsalted and fast, so the same
// password yields the same line on every host. The file is 0600 and never
// leaves the panel; this gate stops casual browsing, it is not a password
// manager. Documented as a limitation rather than presented as stronger.
func authHash(password string) string {
	sum := sha1.Sum([]byte(password))
	return "{SHA}" + base64.StdEncoding.EncodeToString(sum[:])
}

// validateAuth accepts the clear form ("", "") plus a username/password pair.
// The password never reaches nginx config — only its hash does — but control
// characters are still refused so the stored line stays one line and the
// operator cannot smuggle a newline into a later reader.
func validateAuth(username, password string) error {
	if username == "" && password == "" {
		return nil
	}
	if username == "" || password == "" {
		return fmt.Errorf("%w：用户名与口令必须同时给出", ErrInvalid)
	}
	if !authUserRe.MatchString(username) {
		return fmt.Errorf("%w：用户名用 1-32 位字母、数字、点、下划线或连字符，且以字母或数字开头", ErrInvalid)
	}
	runes := utf8.RuneCountInString(password)
	if runes < 8 || runes > 128 {
		return fmt.Errorf("%w：口令长度需要 8-128 个字符", ErrInvalid)
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w：口令不能包含控制字符", ErrInvalid)
		}
	}
	return nil
}

// authLines is the exact server-level block. It is rendered without a location
// wrapper on purpose: the whole vhost is protected, including files that no
// location block matches.
func authLines(s Site) string {
	if s.AuthUser == "" {
		return ""
	}
	return "    auth_basic \"" + authRealm + "\";\n" +
		"    auth_basic_user_file " + s.AuthFile + ";\n"
}

// acmeExemptLocation keeps HTTP-01 renewals working on a TLS site that also
// requires a password. ACME validates over port 80 without credentials, so a
// server-level auth_basic would otherwise turn every renewal into a 401. The
// challenge path serves nothing but the file the issuer just wrote.
func acmeExemptLocation() string {
	return "    location ^~ /.well-known/acme-challenge/ {\n" +
		"        auth_basic off;\n" +
		"        default_type text/plain;\n" +
		"        try_files $uri =404;\n" +
		"    }\n"
}

// writeAuthFile replaces the password file atomically. A failed rename leaves
// the previous file intact, which is what the rollback path expects.
func writeAuthFile(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建口令目录: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".htpasswd-*")
	if err != nil {
		return fmt.Errorf("创建口令文件: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return fmt.Errorf("写入口令文件: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("设置口令文件权限: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭口令文件: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("替换口令文件: %w", err)
	}
	return nil
}

// snapshotAuth reads the previous password file so a failed config write can
// put it back. A missing file is a normal state (auth was off).
func snapshotAuth(path string) (body []byte, existed bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func restoreAuth(path string, body []byte, existed bool) {
	if existed {
		_ = writeAuthFile(path, string(body))
		return
	}
	_ = os.Remove(path)
}

// SetAuth enables, replaces or clears the site's Basic Auth gate. An empty
// username (and password) clears it and removes the password file, which is
// the always-allowed rescue path. The config and the password file are changed
// as one unit: if nginx rejects the new config, both are restored byte for
// byte, so a failed enable cannot leave a vhost pointing at a file it never
// wrote (or a file that no config references).
func (m *Manager) SetAuth(name, username, password string) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	username = strings.TrimSpace(username)
	if err := validateAuth(username, password); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	path := authPath(m.AuthDir, name)

	if username == "" {
		if site.AuthUser == "" {
			return site, nil
		}
		site.AuthUser = ""
		if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
			return Site{}, err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Site{}, fmt.Errorf("删除口令文件: %w", err)
		}
		return site, nil
	}

	prev, existed, err := snapshotAuth(path)
	if err != nil {
		return Site{}, fmt.Errorf("读取口令文件: %w", err)
	}
	if err := writeAuthFile(path, username+":"+authHash(password)+"\n"); err != nil {
		return Site{}, err
	}
	site.AuthUser = username
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		restoreAuth(path, prev, existed)
		return Site{}, err
	}
	return site, nil
}
