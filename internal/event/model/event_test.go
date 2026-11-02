package model

import "testing"

// CategorizePath is the scoping vocabulary the persistence baseline learns on.
// It must map concrete paths to the right coarse class, and never return empty
// (an uncategorised watched write still has to land somewhere learnable).
func TestCategorizePath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/root/.ssh/authorized_keys", "ssh_authorized_keys"},
		{"/home/deploy/.ssh/authorized_keys2", "ssh_authorized_keys"},
		{"/home/deploy/.ssh/config", "ssh_dir"},
		{"/etc/cron.d/backup", "cron"},
		{"/var/spool/cron/crontabs/root", "cron"},
		{"/etc/ld.so.preload", "ld_preload"},
		{"/etc/passwd", "passwd"},
		{"/etc/shadow", "shadow"},
		{"/etc/sudoers.d/evil", "sudoers"},
		{"/etc/systemd/system/backdoor.service", "systemd_unit"},
		{"/var/www/html/uploads/shell.php", "web_php"},
		{"/srv/app/public/x.phtml", "web_php"},
		{"/usr/local/apache2/htdocs/c.jsp", "web_jsp"},
		{"/var/www/site/legacy.aspx", "web_asp"},
		{"/etc/init.d/rootkit", "init_script"},
		{"/etc/profile.d/evil.sh", "shell_rc"},
		{"/root/.bashrc", "shell_rc"},
		{"/home/user/documents/notes.txt", "sensitive_write"},
	}
	for _, c := range cases {
		if got := CategorizePath(c.path); got != c.want {
			t.Errorf("CategorizePath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
	if CategorizePath("/home/user/x") == "" {
		t.Error("CategorizePath must never return empty for a watched write")
	}
}
