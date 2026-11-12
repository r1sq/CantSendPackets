package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// The whole premise of the updater: Windows locks a running program against being
// overwritten, but lets it be renamed. Here the program really is running.
func TestInstallOverARunningProgram(t *testing.T) {
	dir := t.TempDir()
	ping := filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE")
	timeout := filepath.Join(os.Getenv("SystemRoot"), "System32", "HOSTNAME.EXE")
	exe := filepath.Join(dir, "app.exe")
	copyFile(t, ping, exe)

	running := exec.Command(exe, "-n", "30", "127.0.0.1")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		running.Process.Kill()
		running.Wait()
		time.Sleep(200 * time.Millisecond)
	}()
	time.Sleep(300 * time.Millisecond)

	if err := os.WriteFile(exe, []byte("x"), 0o755); err == nil {
		t.Fatal("expected Windows to refuse overwriting a running program")
	}
	replacement, err := os.ReadFile(timeout)
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := Install(exe, replacement)
	if err != nil {
		t.Fatalf("Install while running: %v", err)
	}
	// The new copy must really run from the original path.
	out, err := exec.Command(exe).Output()
	if err != nil {
		t.Fatalf("the new program won't start: %v", err)
	}
	host, _ := os.Hostname()
	if len(out) == 0 || host == "" {
		t.Errorf("unexpected output %q", out)
	}
	// A leftover old copy is still running, so it can't be deleted yet. Cleanup has
	// to cope with that, and the next start retries.
	Cleanup(exe)
	if _, err := os.Stat(exe); err != nil {
		t.Errorf("Cleanup removed the program: %v", err)
	}
	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := exec.Command(exe, "-n", "1", "127.0.0.1").Run(); err != nil {
		t.Errorf("the restored program won't start: %v", err)
	}
}
