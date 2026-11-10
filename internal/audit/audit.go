// Package audit is the append-only operation log.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Lisir2002/Mini_Panel/internal/store"
)

// Entry is one recorded action. Params must already be masked with Mask().
type Entry struct {
	At      time.Time
	User    string
	IP      string
	Geo     string
	Action  string
	Target  string
	Params  map[string]string
	Result  string
	Error   string
	Elapsed time.Duration
}

type Logger struct{ st *store.Store }

func New(st *store.Store) *Logger { return &Logger{st: st} }

func (l *Logger) Write(e Entry) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	if e.Result == "" {
		e.Result = "ok"
	}
	masked := Mask(e.Params)
	keys := make([]string, 0, len(masked))
	for k := range masked {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	hash := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(&sb, "%s=%s ", k, masked[k])
		fmt.Fprintf(hash, "%s\x00%s\x00", k, e.Params[k])
	}
	_, _ = l.st.DB().Exec(`INSERT INTO audit(at,user,ip,geo,action,target,params_hash,params_mask,result,error,duration_ms)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		e.At.Unix(), e.User, e.IP, e.Geo, e.Action, e.Target,
		hex.EncodeToString(hash.Sum(nil)), sb.String(), e.Result, e.Error, e.Elapsed.Milliseconds())
}

// Row is a read-back audit record.
type Row struct {
	ID     int64  `json:"id"`
	At     int64  `json:"at"`
	User   string `json:"user"`
	IP     string `json:"ip"`
	Geo    string `json:"geo"`
	Action string `json:"action"`
	Target string `json:"target"`
	Params string `json:"params_mask"`
	// Hash is a SHA-256 over the *unmasked* parameter values. It is what lets an
	// operator prove two requests carried the same credential, or that a record
	// has not been tampered with, without the trail storing the credential.
	Hash     string `json:"params_hash"`
	Result   string `json:"result"`
	Error    string `json:"error"`
	Duration int64  `json:"duration_ms"`
}

// List returns the newest rows. There is intentionally no delete or truncate
// method on Logger: an audit log the audited party can wipe is decoration.
func (l *Logger) List(limit, offset int) ([]Row, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	var total int
	if err := l.st.DB().QueryRow(`SELECT COUNT(1) FROM audit`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rs, err := l.st.DB().Query(`SELECT id,at,user,ip,geo,action,target,params_mask,params_hash,result,error,duration_ms
		FROM audit ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rs.Close()
	out := []Row{}
	for rs.Next() {
		var r Row
		if err := rs.Scan(&r.ID, &r.At, &r.User, &r.IP, &r.Geo, &r.Action, &r.Target,
			&r.Params, &r.Hash, &r.Result, &r.Error, &r.Duration); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rs.Err()
}

var secretKeys = []string{"password", "passwd", "pass", "secret", "token", "key", "pem",
	"privatekey", "certpem", "db_password", "totp", "cookie", "authorization"}

// Mask redacts credential-shaped values before they reach the log or a hash.
// Commercial panels mask the same shapes in their crash reporters; we apply the
// rule to the audit trail instead, where the leak risk is higher because the
// values are written by design rather than by accident.
func Mask(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		redact := false
		for _, s := range secretKeys {
			if strings.Contains(lk, s) {
				redact = true
				break
			}
		}
		if redact {
			out[k] = "***"
			continue
		}
		if len(v) > 120 {
			v = v[:120] + "…"
		}
		out[k] = v
	}
	return out
}

// Map flattens an arbitrary JSON body into string pairs for masking/logging.
func Map(b []byte) map[string]string {
	out := map[string]string{}
	if len(b) == 0 {
		return out
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return out
	}
	for k, v := range m {
		out[k] = fmt.Sprint(v)
	}
	return out
}
