//go:build linux

// Package loader is the userspace side of the eBPF sensors: it loads the
// compiled CO-RE object, attaches the programs, and exposes the ring buffer as
// a stream of raw event samples. Decoding and enrichment happen downstream so
// this package stays a thin, replaceable bridge to the kernel.
package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// mapName is the shared ring buffer in bpf/programs/sensors.bpf.c. Every program
// in the object (commit_creds, sched_exec, tcp_connect, security_file_open) is a
// tracing program and is attached.
const mapName = "phage_events"

// Sensor is a loaded, attached set of eBPF programs plus their shared ring buffer.
type Sensor struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
}

// Load reads the compiled object at objPath, loads it into the kernel, attaches
// every tracing program it contains, and opens the shared ring buffer.
func Load(objPath string) (*Sensor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec %q: %w", objPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load into kernel: %w", err)
	}

	s := &Sensor{coll: coll}
	for name, prog := range coll.Programs {
		lnk, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("attach %q: %w", name, err)
		}
		s.links = append(s.links, lnk)
	}
	if len(s.links) == 0 {
		s.Close()
		return nil, fmt.Errorf("no programs found in %q", objPath)
	}

	m := coll.Maps[mapName]
	if m == nil {
		s.Close()
		return nil, fmt.Errorf("ring buffer map %q not found", mapName)
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	s.reader = rd
	return s, nil
}

// SetSelfPID tells the kernel sensors the agent's own tgid, arming the
// self-defense programs (they ignore signals/ptrace unless the target is the
// agent). A missing map is not fatal — self-defense is simply inert.
func (s *Sensor) SetSelfPID(pid uint32) error {
	m := s.coll.Maps["self_pid"]
	if m == nil {
		return nil
	}
	return m.Update(uint32(0), pid, ebpf.UpdateAny)
}

// Read returns the next raw event sample. It blocks until a sample arrives or
// the Sensor is closed, in which case it returns ringbuf.ErrClosed.
func (s *Sensor) Read() ([]byte, error) {
	rec, err := s.reader.Read()
	if err != nil {
		return nil, err
	}
	return rec.RawSample, nil
}

// Close detaches the program and releases all kernel resources. Closing the
// reader also unblocks any in-flight Read. It is safe to call more than once.
func (s *Sensor) Close() error {
	var firstErr error
	if s.reader != nil {
		if err := s.reader.Close(); err != nil {
			firstErr = err
		}
		s.reader = nil
	}
	for _, lnk := range s.links {
		lnk.Close()
	}
	s.links = nil
	if s.coll != nil {
		s.coll.Close()
		s.coll = nil
	}
	return firstErr
}
