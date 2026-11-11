package platform

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	mpacme "github.com/Lisir2002/Mini_Panel/internal/acme"
)

func TestMapACMEErrKeepsTheSentinelOnce(t *testing.T) {
	cases := []struct {
		err        error
		sentinel   error
		wantDetail string
	}{
		{fmt.Errorf("%w：*.example.com 是通配符", mpacme.ErrUnsupported), ErrACMEUnsupported, "*.example.com 是通配符"},
		{fmt.Errorf("%w：CA 未通过验证", mpacme.ErrFailed), ErrACMEFailed, "CA 未通过验证"},
		{mpacme.ErrUnsupported, ErrACMEUnsupported, ""},
	}
	for _, c := range cases {
		got := mapACMEErr(c.err)
		if !errors.Is(got, c.sentinel) {
			t.Errorf("mapACMEErr(%v) = %v, not %v", c.err, got, c.sentinel)
			continue
		}
		if strings.Count(got.Error(), c.sentinel.Error()) != 1 {
			t.Errorf("sentinel repeated in %q", got.Error())
		}
		if c.wantDetail != "" && !strings.Contains(got.Error(), c.wantDetail) {
			t.Errorf("%q lost detail %q", got.Error(), c.wantDetail)
		}
	}
	if got := mapACMEErr(errors.New("disk full")); !strings.Contains(got.Error(), "disk full") {
		t.Errorf("unknown error was swallowed: %v", got)
	}
}
