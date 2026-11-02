package profile

import (
	"testing"
	"time"
)

func TestProfileSyscallsSortedAndDeduped(t *testing.T) {
	p := New("web.service", 42, map[int]uint64{59: 1, 0: 100, 1: 100, 257: 3}, 30*time.Second)
	got := p.Syscalls()
	want := []int{0, 1, 59, 257}
	if len(got) != len(want) {
		t.Fatalf("Syscalls() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Syscalls() = %v, want %v", got, want)
		}
	}
}

func TestProfileTotalEvents(t *testing.T) {
	p := New("web.service", 42, map[int]uint64{0: 100, 1: 100, 59: 1}, time.Minute)
	if got := p.TotalEvents(); got != 201 {
		t.Errorf("TotalEvents() = %d, want 201", got)
	}
}

func TestNewCopiesCounts(t *testing.T) {
	src := map[int]uint64{0: 1}
	p := New("x", 1, src, 0)
	src[0] = 999 // mutate the caller's map
	if p.Counts[0] != 1 {
		t.Error("New must copy counts; profile aliased the caller's map")
	}
}
