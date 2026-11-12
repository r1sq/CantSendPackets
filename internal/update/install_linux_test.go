package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func copyProgram(t *testing.T, from, to string) []byte {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Skipf("no %s here: %v", from, err)
	}
	if err := os.WriteFile(to, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return data
}

// Linux lets a running program's file be renamed and replaced; the process keeps
// the old one. The new file must come out executable and really run.
func TestInstallOverARunningProgram(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "app")
	copyProgram(t, "/bin/sleep", exe)

	running := exec.Command(exe, "30")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		running.Process.Kill()
		running.Wait()
	}()
	time.Sleep(100 * time.Millisecond)

	replacement, err := os.ReadFile("/bin/echo")
	if err != nil {
		t.Skip(err)
	}
	if _, err := Install(exe, replacement); err != nil {
		t.Fatalf("Install while running: %v", err)
	}
	out, err := exec.Command(exe, "hello").Output()
	if err != nil || strings.TrimSpace(string(out)) != "hello" {
		t.Fatalf("the new program doesn't run from the original path: %q %v", out, err)
	}
	if running.ProcessState != nil {
		t.Error("the running copy was disturbed")
	}
	Cleanup(exe)
	if _, err := os.Stat(exe); err != nil {
		t.Errorf("Cleanup removed the program: %v", err)
	}
	if _, err := os.Stat(exe + ".old"); err == nil {
		t.Error("Cleanup left the old copy behind; on Linux it can go even while running")
	}
}

func TestRollbackRestoresTheOldProgram(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "app")
	copyProgram(t, "/bin/true", exe)
	replacement, err := os.ReadFile("/bin/false")
	if err != nil {
		t.Skip(err)
	}
	rollback, err := Install(exe, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if exec.Command(exe).Run() == nil {
		t.Fatal("the replacement (false) should be in place")
	}
	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := exec.Command(exe).Run(); err != nil {
		t.Errorf("the restored program (true) won't run: %v", err)
	}
}
