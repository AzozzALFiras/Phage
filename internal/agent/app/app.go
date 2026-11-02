// Package app wires the pipeline together and owns the daemon's run loop. It is
// the one place that knows about every stage; each stage still knows only its
// neighbours. Keeping the wiring here lets cmd/phaged stay a thin entrypoint.
package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
	"github.com/AzozzALFiras/Phage/internal/analysis/scorer"
	"github.com/AzozzALFiras/Phage/internal/analysis/scorer/behavioral"
	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/audit"
	"github.com/AzozzALFiras/Phage/internal/control"
	"github.com/AzozzALFiras/Phage/internal/enrich"
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
	"github.com/AzozzALFiras/Phage/internal/honeytoken"
	"github.com/AzozzALFiras/Phage/internal/policy/engine"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/response/action"
	"github.com/AzozzALFiras/Phage/internal/response/contain"
	"github.com/AzozzALFiras/Phage/internal/selfprotect"
	"github.com/AzozzALFiras/Phage/internal/sensor/decode"
	"github.com/AzozzALFiras/Phage/internal/sensor/loader"
	"github.com/AzozzALFiras/Phage/internal/store/profile"
)

// App is a configured, runnable daemon.
type App struct {
	cfg           config.Config
	objPath       string
	store         profile.Repository
	profile       *baseline.Profile
	enricher      enrich.Enricher
	extract       feature.Privilege
	execExtract   feature.Exec
	netExtract    feature.Network
	fileExtract   feature.Filesystem
	enableExtract feature.Enable
	scorer        scorer.Scorer
	engine        *engine.Engine
	freezer       *contain.Freezer
	audit         *audit.Writer

	started time.Time
	// counters and the recent-alerts ring back the control interface.
	mu          sync.Mutex
	nEvents     uint64
	nAlerts     uint64
	nContained  uint64
	recent      []control.Alert
	recentLimit int
}

// New builds an App from config, the path to the compiled eBPF object, and the
// repository used to persist the learned baseline.
func New(cfg config.Config, objPath string, store profile.Repository) *App {
	p := baseline.NewProfile()
	return &App{
		cfg:         cfg,
		objPath:     objPath,
		store:       store,
		profile:     p,
		extract:     feature.Privilege{},
		scorer:      behavioral.New(p), // bound to p; sees whatever we load into it
		engine:      engine.NewWithThresholds(cfg.Mode, engine.Thresholds(cfg.Thresholds)),
		freezer:     contain.NewFreezer(),
		started:     time.Now(),
		recentLimit: 100,
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

	// Arm self-defense: tell the kernel sensors our own pid so they flag any
	// signal/ptrace aimed at the agent (anti-blinding).
	if err := sensor.SetSelfPID(uint32(os.Getpid())); err != nil {
		log.Printf("self-defense arm: %v", err)
	}
	go a.deadMansSwitch(ctx)

	// Opt-in honeytokens: plant decoy credential files and alert on any read.
	if a.cfg.Honeytokens {
		paths, inodes := honeytoken.Seed()
		if len(inodes) == 0 {
			log.Printf("honeytokens: none planted (decoy paths already exist?)")
		} else if err := sensor.SetHoneytokens(inodes); err != nil {
			log.Printf("honeytokens: %v", err)
		} else {
			defer honeytoken.Remove(paths)
			log.Printf("honeytokens planted: %d decoys — any read of one is a high-confidence alert", len(paths))
		}
	}

	// Opt-in tamper-resistance: deny signals that would kill the agent. Loaded as
	// a separate eBPF-LSM object so a kernel without BPF LSM still runs the agent.
	if a.cfg.Protect {
		if !selfprotect.Available() {
			log.Printf("self-protection requested (-protect) but BPF LSM is not active; running without it")
		} else {
			objPath := filepath.Join(filepath.Dir(a.objPath), "selfprotect.bpf.o")
			g, err := selfprotect.Arm(objPath, uint32(os.Getpid()), uint32(os.Getppid()))
			if err != nil {
				log.Printf("self-protection: %v; running without it", err)
			} else {
				defer g.Close()
				log.Printf("self-protection ARMED: signals that would kill the agent are denied (except from pid 1 / launcher); systemctl stop and reboot still work")
			}
		}
	}

	log.Printf("sensors attached (creds, exec, egress, files, kernel-enabling ops, self-defense); mode=%s obj=%s", a.cfg.Mode, a.objPath)

	if srv, err := control.Serve(ctx, a.cfg.ControlPath, a); err != nil {
		log.Printf("control socket disabled: %v", err)
	} else if srv != nil {
		defer srv.Close()
		log.Printf("control socket: %s", a.cfg.ControlPath)
	}

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

		// Self-defense is not a learned/averaged signal: an attempt to kill,
		// stop, or ptrace the agent by anything other than its supervisor is
		// intrinsically critical and is surfaced in every mode (including learn).
		if ev.Kind == kind.SelfDefense {
			a.mu.Lock()
			a.nEvents++
			a.mu.Unlock()
			a.respondSelfDefense(ev)
			continue
		}

		// A read of a planted decoy is intrinsically high-confidence (nothing
		// legitimate references it) — surfaced directly, not via the baseline.
		if ev.Kind == kind.Honeytoken {
			a.mu.Lock()
			a.nEvents++
			a.mu.Unlock()
			a.respondHoneytoken(ev)
			continue
		}

		var vec feature.Vector
		switch ev.Kind {
		case kind.Exec:
			vec = a.execExtract.Extract(ev)
		case kind.Connect:
			vec = a.netExtract.Extract(ev)
		case kind.FileWrite:
			vec = a.fileExtract.Extract(ev)
		case kind.Enable:
			vec = a.enableExtract.Extract(ev)
		default:
			vec = a.extract.Extract(ev)
		}

		a.mu.Lock()
		a.nEvents++
		a.mu.Unlock()

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
	parent := ev.ParentComm
	if parent == "" && len(ev.Lineage) > 0 {
		parent = ev.Lineage[0].Comm
	}
	reason := reasons(v)
	// For egress anomalies, the concrete destination is the operator's first
	// question; keep it in the reason and the audit trail even though the IP is
	// deliberately not a learned feature.
	if ev.Kind == kind.Connect && ev.Net.DestIP != "" {
		reason = fmt.Sprintf("%s (-> %s:%d)", reason, ev.Net.DestIP, ev.Net.DestPort)
	}
	// For persistence anomalies, the concrete file written is the operator's
	// first question; keep it in the reason and the audit trail even though the
	// learned feature is the coarse class, not the path.
	if ev.Kind == kind.FileWrite && ev.File.Path != "" {
		reason = fmt.Sprintf("%s (wrote %s)", reason, ev.File.Path)
	}
	if ev.Kind == kind.Enable && ev.EnableOp != "" {
		reason = fmt.Sprintf("%s (op: %s)", reason, ev.EnableOp)
	}
	log.Printf("%s score=%.2f action=%s pid=%d comm=%q parent=%q uid=%d->euid=%d interactive=%t :: %s",
		strings.ToUpper(labelFor(v.Score)), v.Score, act.Type,
		ev.PID, ev.Comm, parent, ev.Creds.UID, ev.Creds.EUID, ev.Session.Interactive, reason)

	a.audit.Record(audit.Entry{
		Action: string(act.Type), Score: v.Score, PID: ev.PID, Comm: ev.Comm, Reason: reason,
	})

	contained := false
	if act.Type == action.Freeze {
		if ok, why := containmentSafe(ev); !ok {
			log.Printf("CONTAIN pid=%d comm=%q SKIPPED (%s) — alert only", ev.PID, ev.Comm, why)
		} else if err := a.freezer.Freeze(ev.PID); err != nil {
			log.Printf("CONTAIN pid=%d failed: %v", ev.PID, err)
		} else {
			contained = true
			log.Printf("CONTAIN pid=%d comm=%q FROZEN (process tree quarantined, reversible)", ev.PID, ev.Comm)
		}
	}

	a.mu.Lock()
	a.nAlerts++
	if contained {
		a.nContained++
	}
	a.recent = append(a.recent, control.Alert{
		Time: time.Now().UTC().Format(time.RFC3339), Score: v.Score,
		Action: string(act.Type), PID: ev.PID, Comm: ev.Comm, Reason: reason,
	})
	if len(a.recent) > a.recentLimit {
		a.recent = a.recent[len(a.recent)-a.recentLimit:]
	}
	a.mu.Unlock()
}

// Status implements control.Handler.
func (a *App) Status() control.Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return control.Status{
		Mode:      a.cfg.Mode.String(),
		Uptime:    time.Since(a.started).Truncate(time.Second).String(),
		Events:    a.nEvents,
		Alerts:    a.nAlerts,
		Contained: a.nContained,
	}
}

// RecentAlerts implements control.Handler: the last n surfaced verdicts.
func (a *App) RecentAlerts(n int) []control.Alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n > len(a.recent) {
		n = len(a.recent)
	}
	out := make([]control.Alert, n)
	copy(out, a.recent[len(a.recent)-n:])
	return out
}

// Thaw implements control.Handler: release a quarantined process (false positive).
func (a *App) Thaw(pid int32) error {
	return a.freezer.Thaw(pid)
}

// supervisorComms may legitimately send the agent a stop signal (service
// shutdown). A lethal signal from anything else is treated as a tamper attempt.
var supervisorComms = map[string]bool{
	"systemd": true, "init": true, "systemd-shutdow": true,
}

// respondSelfDefense handles an attack on the agent itself. It is deliberately
// outside the learned scorer: tampering with the monitor is self-evidently
// hostile and must surface even on a thin/empty baseline. The only benign case
// is the service supervisor sending a stop signal during shutdown.
func (a *App) respondSelfDefense(ev model.Event) {
	if ev.SelfDefOp != "ptrace" && supervisorComms[ev.Comm] {
		return // legitimate service stop by the supervisor
	}
	detail := fmt.Sprintf("attempt to tamper with the Phage agent: %s by %q (pid %d) — monitor blinding/kill attempt",
		ev.SelfDefOp, ev.Comm, ev.PID)
	v := verdict.Verdict{
		Score:   1.0,
		Reasons: []verdict.Reason{{Feature: "self.tamper", Contribution: 1.0, Detail: detail}},
	}
	act := action.Action{Type: action.Notify}
	if a.cfg.Mode == mode.Enforce {
		act.Type = action.Freeze // contain the tamperer (subject to containmentSafe)
	}
	a.respond(ev, v, act)
}

// respondHoneytoken handles a read of a planted decoy. Nothing legitimate reads
// these files, so it is a near-zero-false-positive, top-severity verdict surfaced
// in every mode; the agent itself is excluded (it plants them).
func (a *App) respondHoneytoken(ev model.Event) {
	if ev.Comm == "phaged" {
		return
	}
	detail := fmt.Sprintf("read a planted honeytoken decoy %q — near-certain credential theft / intruder snooping", ev.File.Path)
	v := verdict.Verdict{
		Score:   1.0,
		Reasons: []verdict.Reason{{Feature: "honeytoken", Contribution: 1.0, Detail: detail}},
	}
	act := action.Action{Type: action.Notify}
	if a.cfg.Mode == mode.Enforce {
		act.Type = action.Freeze
	}
	a.respond(ev, v, act)
}

// deadMansSwitch is the anti-blinding heartbeat: if the event stream was active
// and then goes silent, the agent's sensors may have been detached or disabled.
// Rule engines cannot detect the *absence* of telemetry; Phage can. It only
// warns when a previously-busy stream stops, so an idle host stays quiet.
func (a *App) deadMansSwitch(ctx context.Context) {
	const window = 30 * time.Second
	t := time.NewTicker(window)
	defer t.Stop()
	var last uint64
	var ewma float64 // smoothed events-per-window
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.mu.Lock()
			now := a.nEvents
			a.mu.Unlock()
			delta := now - last
			last = now
			if first { // prime, don't judge the first window
				first = false
				ewma = float64(delta)
				continue
			}
			// Warn only if the stream was meaningfully active and just stopped.
			if delta == 0 && ewma >= 20 {
				log.Printf("CRITICAL self-defense: telemetry stopped unexpectedly (was ~%.0f events/%s, now 0) — sensors may be disabled or blinded", ewma, window)
			}
			ewma = 0.5*ewma + 0.5*float64(delta)
		}
	}
}

// criticalComms is a hard safety allowlist: processes Phage must never freeze,
// because doing so could lock an operator out of the machine or wedge the
// system. This is a deliberate hardcoded guardrail (not a learned signal) — it
// exists because enforce mode once froze SSH logins and locked the box out.
var criticalComms = map[string]bool{
	"sshd": true, "systemd": true, "init": true, "login": true,
	"agetty": true, "getty": true, "systemd-logind": true,
	"dbus-daemon": true, "phaged": true, "systemd-journal": true,
}

// containmentSafe decides whether a process may be frozen. It refuses to
// contain (a) anything backed by an interactive login session — never lock out
// the admin path; (b) control-plane processes or their children; and (c)
// anything that is not an actual privilege escalation — exec-pattern anomalies
// alert but never freeze, since they are far more prone to false positives.
func containmentSafe(ev model.Event) (bool, string) {
	if ev.Session.Interactive {
		return false, "interactive login session"
	}
	if criticalComms[ev.Comm] || criticalComms[ev.ParentComm] {
		return false, "control-plane process"
	}
	if !ev.RaisedToRoot() {
		return false, "not a privilege escalation"
	}
	return true, ""
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
