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

// progName and mapName must match the symbols in bpf/programs/privilege/creds.bpf.c.
const (
	progName = "on_commit_creds"
	mapName  = "phage_events"
)

// Sensor is a loaded, attached eBPF program plus its event ring buffer.
type Sensor struct {
	coll   *ebpf.Collection
	link   link.Link
	reader *ringbuf.Reader
}

// Load reads the compiled object at objPath, loads it into the kernel, attaches
// the commit_creds fentry program, and opens its ring buffer for reading.
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

	prog := coll.Programs[progName]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("program %q not found in %q", progName, objPath)
	}

	lnk, err := link.AttachTracing(link.TracingOptions{Program: prog})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach %q: %w", progName, err)
	}

	m := coll.Maps[mapName]
	if m == nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("ring buffer map %q not found", mapName)
	}

	rd, err := ringbuf.NewReader(m)
	if err != nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	return &Sensor{coll: coll, link: lnk, reader: rd}, nil
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
	if s.link != nil {
		s.link.Close()
		s.link = nil
	}
	if s.coll != nil {
		s.coll.Close()
		s.coll = nil
	}
	return firstErr
}
