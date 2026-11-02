package enforce

import "testing"

func TestBPFInLSMList(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"active, bpf present", "lockdown,capability,landlock,yama,apparmor,bpf,ima,evm\n", true},
		{"bpf appended", "capability,bpf", true},
		{"only bpf", "bpf", true},
		{"absent", "lockdown,capability,landlock,yama,apparmor,ima,evm", false},
		{"empty", "", false},
		{"substring must not match", "bpfoo,capability", false},
		{"whitespace tolerated", " capability , bpf , yama ", true},
	}
	for _, c := range cases {
		if got := bpfInLSMList(c.content); got != c.want {
			t.Errorf("%s: bpfInLSMList(%q) = %v, want %v", c.name, c.content, got, c.want)
		}
	}
}
