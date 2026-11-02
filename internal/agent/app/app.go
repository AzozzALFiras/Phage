// Package app wires the pipeline together and owns the daemon's run loop. It is
// the one place that knows about every stage; each stage still knows only its
// neighbours. Keeping the wiring here lets cmd/phaged stay a thin entrypoint.
package app

import (
	"context"
	"log"
	"strings"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
	"github.com/AzozzALFiras/Phage/internal/analysis/scorer"
	"github.com/AzozzALFiras/Phage/internal/analysis/scorer/behavioral"
	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/audit"
	"github.com/AzozzALFiras/Phage/internal/enrich"
	"github.com/AzozzALFiras/Phage/internal/event/model"
	"github.com/AzozzALFiras/Phage/internal/policy/engine"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/response/action"
	"github.com/AzozzALFiras/Phage/internal/response/contain"
	"github.com/AzozzALFiras/Phage/internal/sensor/decode"
	"github.com/AzozzALFiras/Phage/internal/sensor/loader"
	"github.com/AzozzALFiras/Phage/internal/store/profile"
)

// App is a configured, runnable daemon.
type App struct {
	cfg      config.Config
	objPath  string
	store    profile.Repository
	profile  *baseline.Profile
	enricher enrich.Enricher
	extract  feature.Privilege
	scorer   scorer.Scorer
	engine   *engine.Engine
	freezer  *contain.Freezer
	audit    *audit.Writer
}

// New builds an App from config, the path to the compiled eBPF object, and the
// repository used to persist the learned baseline.
func New(cfg config.Config, objPath string, store profile.Repository) *App {
	p := baseline.NewProfile()
	return &App{
		cfg:     cfg,
		objPath: objPath,
		store:   store,
		profile: p,
		extract: feature.Privilege{},
		scorer:  behavioral.New(p), // bound to p; sees whatever we load into it
		engine:  engine.New(cfg.Mode),
		freezer: contain.NewFreezer(),
	}
}

// Run loads the baseline and the sensor, then processes events until ctx is
// cancelled. In learn mode it updates and persists the baseline; in alert/
// enforce mode it scores each event against the baseline and acts via the
// policy engine.
func (a *App) Run(ctx context.Context) error {
	if err := a.store.Load(a.profile); err != nil {
		return err
	}

	aw, err := audit.Open(a.cfg.AuditPath)
	if err != nil {
		return err
	}
	a.audit = aw
	defer a.audit.Close()

	sensor, err := loader.Load(a.objPath)
	if err != nil {
		return err
	}
	defer sensor.Close()

	// Cancelling the context closes the sensor, which unblocks Read below.
	go func() {
		<-ctx.Done()
		sensor.Close()
	}()

	log.Printf("sensor attached (commit_creds); mode=%s obj=%s", a.cfg.Mode, a.objPath)

	for {
		raw, err := sensor.Read()
		if err != nil {
			if ctx.Err() != nil {
				return a.onShutdown() // clean shutdown
			}
			return err
		}

		ev, err := decode.Event(raw)
		if err != nil {
			log.Printf("decode: %v", err)
			continue
		}
		ev = a.enricher.Enrich(ev)
		vec := a.extract.Extract(ev)

		if a.cfg.Mode == mode.Learn {
			for k, v := range vec {
				a.profile.Observe(k, v)
			}
			continue
		}

		// alert / enforce: score against the learned baseline and let the policy
		// engine decide how forcefully to respond.
		v := a.scorer.Score(vec)
		act := a.engine.Decide(v, ev.PID)
		if act.Type != action.None {
			a.respond(ev, v, act)
		}
	}
}

// onShutdown persists the baseline when we have been learning.
func (a *App) onShutdown() error {
	if a.cfg.Mode != mode.Learn {
		return nil
	}
	if err := a.store.Save(a.profile); err != nil {
		log.Printf("save baseline: %v", err)
		return err
	}
	log.Printf("baseline saved")
	return nil
}

// respond logs the verdict, records it to the audit trail, and carries out the
// action. Containment is attempted only in enforce mode (where the engine emits
// Freeze); alert mode only ever yields Notify.
func (a *App) respond(ev model.Event, v verdict.Verdict, act action.Action) {
	parent := ""
	if len(ev.Lineage) > 0 {
		parent = ev.Lineage[0].Comm
	}
	reason := reasons(v)
	log.Printf("%s score=%.2f action=%s pid=%d comm=%q parent=%q uid=%d->euid=%d interactive=%t :: %s",
		strings.ToUpper(labelFor(v.Score)), v.Score, act.Type,
		ev.PID, ev.Comm, parent, ev.Creds.UID, ev.Creds.EUID, ev.Session.Interactive, reason)

	a.audit.Record(audit.Entry{
		Action: string(act.Type), Score: v.Score, PID: ev.PID, Comm: ev.Comm, Reason: reason,
	})

	if act.Type == action.Freeze {
		if err := a.freezer.Freeze(ev.PID); err != nil {
			log.Printf("CONTAIN pid=%d failed: %v", ev.PID, err)
			return
		}
		log.Printf("CONTAIN pid=%d comm=%q FROZEN (process tree quarantined, reversible)", ev.PID, ev.Comm)
	}
}

// labelFor is a coarse display bucket; the policy engine, not this, decides
// what to do about a score.
func labelFor(score float64) string {
	switch {
	case score >= 0.8:
		return "critical"
	case score >= 0.4:
		return "alert"
	default:
		return "notice"
	}
}

func reasons(v verdict.Verdict) string {
	if len(v.Reasons) == 0 {
		return "(no anomalous features)"
	}
	parts := make([]string, 0, len(v.Reasons))
	for _, r := range v.Reasons {
		parts = append(parts, r.Detail)
	}
	return strings.Join(parts, "; ")
}
