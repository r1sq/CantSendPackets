package npcap

import "testing"

func TestVersionReportsRatherThanCrashes(t *testing.T) {
	v, err := Version()
	t.Logf("Npcap: version %q, err %v", v, err)
	if err == nil && v == "" {
		t.Error("loaded but reported no version")
	}
	if err == nil {
		return
	}
	if _, err := Open("{00000000-0000-0000-0000-000000000000}"); err == nil {
		t.Error("Open should fail with Npcap absent")
	}
}
