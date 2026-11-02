// Command phage-jail is the operator tool for auto-jail (M3): it learns the
// syscalls a running service makes and generates a least-privilege seccomp
// policy from them. Enforcement is handed to systemd/seccomp, not reinvented —
// see docs/concepts/auto-jail.md.
//
//	phage-jail -unit nginx.service -bpf bpf/build/jail.bpf.o -seconds 120 -out ./profiles
//
// It needs root and a Linux kernel with BTF. The generated profile is a starting
// point to validate in staging, never a blind drop-in.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/AzozzALFiras/Phage/internal/jail/cgroup"
	"github.com/AzozzALFiras/Phage/internal/jail/profile"
	"github.com/AzozzALFiras/Phage/internal/jail/seccomp"
	"github.com/AzozzALFiras/Phage/internal/jail/sensor"
)

var version = "dev"

func main() {
	log.SetFlags(0)
	log.SetPrefix("phage-jail: ")

	var (
		unit    = flag.String("unit", "", "systemd unit to profile (e.g. nginx.service)")
		cgPath  = flag.String("path", "", "cgroup v2 path to profile instead of -unit (e.g. /system.slice/app.service)")
		objPath = flag.String("bpf", "bpf/build/jail.bpf.o", "path to the compiled jail eBPF object")
		seconds = flag.Int("seconds", 60, "how long to observe (0 = until Ctrl-C)")
		outDir  = flag.String("out", ".", "directory to write the generated profile into")
		follow  = flag.Bool("follow", false, "re-resolve the unit's cgroup across restarts (so you can restart it to capture startup syscalls)")
	)
	flag.Parse()

	if err := run(*unit, *cgPath, *objPath, *seconds, *outDir, *follow); err != nil {
		log.Fatal(err)
	}
}

func run(unit, cgPath, objPath string, seconds int, outDir string, follow bool) error {
	if unit == "" && cgPath == "" {
		return fmt.Errorf("give -unit or -path (see -h)")
	}
	if !cgroup.MountedV2() {
		return fmt.Errorf("cgroup v2 is required (the profiler attributes syscalls by cgroup id)")
	}

	cgid, resolved, err := resolveCgroup(unit, cgPath)
	if err != nil {
		return err
	}
	label := unit
	if label == "" {
		label = cgPath
	}
	log.Printf("profiling %s (cgroup %s, id %d) for %s via %s",
		label, resolved, cgid, windowDesc(seconds), objPath)

	prof, err := sensor.Open(objPath, cgid)
	if err != nil {
		return err
	}
	defer prof.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if follow {
		if unit == "" {
			return fmt.Errorf("-follow needs -unit (it re-resolves the unit's cgroup)")
		}
		log.Printf("following %s across restarts — restart it now to capture startup syscalls", unit)
		go followUnit(ctx, prof, unit, cgid)
	}

	start := time.Now()
	waitForWindow(ctx, seconds)
	dur := time.Since(start)

	counts, err := prof.Snapshot()
	if err != nil {
		return err
	}
	p := profile.New(label, cgid, counts, dur)
	if p.TotalEvents() == 0 {
		return fmt.Errorf("observed 0 syscalls — did the service do any work during the window? (it must be running and active)")
	}

	return emit(p, outDir)
}

func resolveCgroup(unit, cgPath string) (uint64, string, error) {
	if unit != "" {
		return cgroup.IDForUnit(unit)
	}
	id, err := cgroup.IDForPath(cgPath)
	return id, cgPath, err
}

func waitForWindow(ctx context.Context, seconds int) {
	if seconds <= 0 {
		log.Printf("observing until Ctrl-C ...")
		<-ctx.Done()
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Duration(seconds) * time.Second):
	}
}

// followUnit polls the unit's cgroup id and re-points the profiler whenever it
// changes. A systemd unit gets a fresh cgroup id on each restart, so following
// it is how a restart during the window captures the service's startup syscalls.
// Polling is tight (every 50ms) so the new instance is picked up before it gets
// far past its own startup.
func followUnit(ctx context.Context, prof *sensor.Profiler, unit string, current uint64) {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			id, _, err := cgroup.IDForUnit(unit)
			if err != nil || id == 0 || id == current {
				continue
			}
			if err := prof.SetTarget(id); err != nil {
				log.Printf("follow: set target %d: %v", id, err)
				continue
			}
			log.Printf("follow: cgroup changed %d -> %d (service restarted)", current, id)
			current = id
		}
	}
}

// emit writes the profile artifacts and prints the operator-facing summary.
func emit(p *profile.Profile, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	base := filepath.Join(outDir, sanitize(p.Unit))

	allowed, err := seccomp.Allowed(p)
	if err != nil {
		return err
	}
	oci, err := seccomp.OCI(p)
	if err != nil {
		return err
	}
	dropin, err := seccomp.SystemdDropin(p)
	if err != nil {
		return err
	}
	blocked, err := seccomp.Blocked(p)
	if err != nil {
		return err
	}
	netIsolated, err := seccomp.NetworkIsolated(p)
	if err != nil {
		return err
	}

	files := map[string][]byte{
		base + ".seccomp.json": append(oci, '\n'),
		base + ".dropin.conf":  []byte(dropin),
	}
	for name, data := range files {
		if err := os.WriteFile(name, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	fmt.Printf("\n== profile for %s ==\n", p.Unit)
	fmt.Printf("observed %d syscall invocations over %s\n", p.TotalEvents(), p.Duration.Round(time.Second))
	fmt.Printf("distinct syscalls used: %d; profile allows %d (used + minimal baseline)\n",
		len(p.Syscalls()), len(allowed))
	if len(blocked) > 0 {
		fmt.Printf("blast-radius reduction — denied high-risk syscalls:\n  %s\n", strings.Join(blocked, " "))
		fmt.Printf("=> once jailed, an exploit of this service cannot use the above.\n")
	} else {
		fmt.Printf("note: this service used every high-risk syscall we track; the jail still\n")
		fmt.Printf("      denies everything else, but review whether it needs them all.\n")
	}
	if netIsolated {
		fmt.Printf("network: the service never used a socket — the jail denies ALL networking,\n")
		fmt.Printf("         so a reverse shell or data exfil cannot leave this service.\n")
	}
	fmt.Printf("\nwrote:\n  %s.seccomp.json   (OCI; docker --security-opt seccomp=...)\n", base)
	fmt.Printf("  %s.dropin.conf    (systemctl edit %s, paste, restart)\n", base, p.Unit)
	fmt.Printf("\nValidate in staging before trusting: the default action is EPERM, so a\n")
	fmt.Printf("missed syscall surfaces in the service log rather than killing it.\n")
	return nil
}

func sanitize(s string) string {
	s = strings.TrimSuffix(s, ".service")
	s = strings.ReplaceAll(s, "/", "_")
	if s == "" {
		return "service"
	}
	return s
}

func windowDesc(seconds int) string {
	if seconds <= 0 {
		return "until interrupted"
	}
	return (time.Duration(seconds) * time.Second).String()
}
