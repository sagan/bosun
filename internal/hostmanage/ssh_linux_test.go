//go:build linux

package hostmanage

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run only in an isolated test environment. This invokes sshd's config parser,
// never starts an SSH server or modifies /etc/ssh.
func TestHostRealSSHConfig(t *testing.T) {
	if os.Getenv("BOSUN_TEST_HOST_SSH") != "1" {
		t.Skip("set BOSUN_TEST_HOST_SSH=1 for real OpenSSH parser")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, e := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); e != nil {
		t.Fatalf("key generation: %v %s", e, out)
	}
	original := "HostKey " + key + "\nPort 22\nPort 2222\nPasswordAuthentication yes\nUsePAM no\n"
	settings := map[string]string{"Port": "22\n2022", "PasswordAuthentication": "no", "PermitRootLogin": "no", "PubkeyAuthentication": "yes", "KbdInteractiveAuthentication": "no"}
	path := filepath.Join(dir, "sshd_config")
	check := func(text string, want []string) {
		t.Helper()
		if e := os.WriteFile(path, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		cmd := exec.CommandContext(ctx, "/usr/sbin/sshd", "-T", "-f", path)
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("sshd: %v %s", e, out)
		}
		ports := []string{}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "port ") {
				ports = append(ports, strings.TrimPrefix(line, "port "))
			}
		}
		if strings.Join(ports, ",") != strings.Join(want, ",") {
			t.Fatalf("effective ports %v want %v", ports, want)
		}
		if !strings.Contains(string(out), "passwordauthentication no\n") {
			t.Fatal("policy not effective")
		}
	}
	dual := sshConfig(original, settings)
	check(dual, []string{"22", "2022"})
	settings["Port"] = "2022"
	check(sshConfig(dual, settings), []string{"2022"})
}
