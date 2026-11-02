// Package enrich turns a bare kernel event into one with enough context to
// judge: process ancestry, the executable, the controlling terminal, and the
// session provenance. It reads /proc best-effort, so a process that has already
// exited simply yields a less-complete event rather than an error.
package enrich

import (
	"fmt"

	"github.com/AzozzALFiras/Phage/internal/enrich/process"
	"github.com/AzozzALFiras/Phage/internal/event/model"
)

// maxLineage bounds how far up the ancestry we walk. A handful of levels is
// enough to see "network service -> shell -> root" without walking to init.
const maxLineage = 6

// Enricher adds process and identity context to events. It holds no state, so
// it is safe to share.
type Enricher struct{}

// Enrich returns ev with lineage, exe, tty, and session provenance filled in
// where /proc still has them.
func (Enricher) Enrich(ev model.Event) model.Event {
	if st, err := process.ReadStat(ev.PID); err == nil {
		if ev.PPID == 0 {
			ev.PPID = st.PPID
		}
		if st.TTYNr != 0 {
			ev.Session.TTY = fmt.Sprintf("tty:%d", st.TTYNr)
		}
	}
	if ev.Exe == "" {
		ev.Exe = process.Exe(ev.PID)
	}
	ev.Lineage = process.Lineage(ev.PID, maxLineage)

	// Session provenance (loginuid) is already set by the decoder from the
	// kernel event — race-free — so enrichment leaves it alone.
	return ev
}
