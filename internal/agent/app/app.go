// Package app wires the pipeline together and owns the daemon's run loop. It is
// the one place that knows about every stage; each stage still knows only its
// neighbours. Keeping the wiring here lets cmd/phaged stay a thin entrypoint.
package app

import (
	"context"
	"log"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/sensor/decode"
	"github.com/AzozzALFiras/Phage/internal/sensor/loader"
)

// App is a configured, runnable daemon.
type App struct {
	cfg     config.Config
	objPath string
	profile *baseline.Profile
	extract feature.Privilege
}

// New builds an App from config and the path to the compiled eBPF object.
func New(cfg config.Config, objPath string) *App {
	return &App{
		cfg:     cfg,
		objPath: objPath,
		profile: baseline.NewProfile(),
		extract: feature.Privilege{},
	}
}

// Run loads the sensor and processes events until ctx is cancelled. In learn
// mode it only updates the baseline; scoring and response are wired in later
// milestones.
func (a *App) Run(ctx context.Context) error {
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
				return nil // clean shutdown
			}
			return err
		}

		ev, err := decode.Event(raw)
		if err != nil {
			log.Printf("decode: %v", err)
			continue
		}

		vec := a.extract.Extract(ev)
		if a.cfg.Mode == mode.Learn {
			for k, v := range vec {
				a.profile.Observe(k, v)
			}
		}

		// First-light observability: prove events flow end to end. Scoring and
		// alerting replace this log in the next milestone.
		log.Printf("event pid=%d comm=%q uid=%d euid=%d root=%t caps=%#x",
			ev.PID, ev.Comm, ev.Creds.UID, ev.Creds.EUID, ev.GainedRoot(), ev.Creds.CapEffective)
	}
}
