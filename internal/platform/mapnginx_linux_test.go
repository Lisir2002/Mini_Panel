package platform

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/nginx"
)

// The TLS writer's errors already start with nginx.ErrTLSInvalid's sentence.
// Wrapping with the platform sentinel must keep that sentence exactly once and
// keep the detail (which domain failed, which PEM was bad).
func TestMapNginxErrDoesNotRepeatTheTLSReason(t *testing.T) {
	raw := fmt.Errorf("%w：证书不覆盖域名 a.example.com", nginx.ErrTLSInvalid)
	got := mapNginxErr(raw)
	if !errors.Is(got, ErrSiteTLSInvalid) {
		t.Fatalf("mapped error does not wrap ErrSiteTLSInvalid: %v", got)
	}
	msg := got.Error()
	if n := strings.Count(msg, "站点证书不合法"); n != 1 {
		t.Errorf("sentinel appears %d times in %q", n, msg)
	}
	if !strings.Contains(msg, "证书不覆盖域名 a.example.com") {
		t.Errorf("detail lost: %q", msg)
	}
}
