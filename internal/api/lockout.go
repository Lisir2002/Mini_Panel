package api

import (
	"net/http"

	"github.com/Lisir2002/Mini_Panel/internal/lockout"
)

// handleLockoutRisks is GET /api/v1/lockout-risks: the 「CLI 对照」table from
// docs/功能设计.md §3.10, served from the same function `minipanel doctor` uses.
//
// It is read-only for a reason that outlives this milestone. Every row's remedy
// is a command run on the machine, and the panel deliberately has no endpoint that
// would run one — a control that could execute `reset-ips` would be the same
// primitive as the reflection endpoints §1.6 of the design doc refuses to build.
// So the page can tell the operator what to type; it cannot type it for them, and
// it cannot be used to undo a lockout from the browser that the lockout just
// closed. That asymmetry is the design, not a missing button.
//
// The same reasoning is why this endpoint is not under the password gate's three
// allowed paths: reading the table is not how you get out of a gate that only
// asks for a new password.
func (s *Server) handleLockoutRisks(w http.ResponseWriter, r *http.Request) {
	items := lockout.Risks(s.Store, s.Cfg)
	armed := 0
	for _, it := range items {
		if it.Armed {
			armed++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"armed": armed,
		"total": len(items),
		// The contract the UI prints: these strings are suggestions, and there is
		// no API that takes them. Stated by the backend so the page cannot quietly
		// grow a "run it for me" button without this field changing.
		"executable": false,
	})
}
