package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r1sq/CantSendPackets/internal/proxy"
)

func TestMissingFileGivesDefaults(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "none.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.ProxyMode != proxy.OverrideAuto || !s.Discoverable {
		t.Errorf("%+v", s)
	}
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "settings.json")
	in := Settings{ProxyMode: proxy.OverrideManual, ProxyAddress: "proxy:8080", ProxyBypass: "*.intern", TrustedProxies: []string{"a:1"}, Discoverable: false}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.ProxyAddress != "proxy:8080" || out.Discoverable || len(out.TrustedProxies) != 1 {
		t.Errorf("%+v", out)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestOlderFileKeepsNewDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(path, []byte(`{"proxyMode":"direct"}`), 0o600)
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Discoverable || !s.CheckUpdates || s.ProxyMode != proxy.OverrideDirect || s.TrustedProxies == nil {
		t.Errorf("a field missing from the file must keep its default: %+v", s)
	}
}

func TestBadFilesFallBackToDefaultsWithAnError(t *testing.T) {
	for name, content := range map[string]string{
		"corrupt": `{not json`,
		"invalid": `{"proxyMode":"manual","proxyAddress":""}`,
	} {
		path := filepath.Join(t.TempDir(), "s.json")
		os.WriteFile(path, []byte(content), 0o600)
		s, err := Load(path)
		if err == nil {
			t.Errorf("%s: no error", name)
		}
		if s.ProxyMode != proxy.OverrideAuto || !s.Discoverable {
			t.Errorf("%s: %+v", name, s)
		}
	}
}

func TestNoPasswordFieldExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	Save(path, Default())
	data, _ := os.ReadFile(path)
	if strings.Contains(strings.ToLower(string(data)), "password") {
		t.Errorf("passwords must never reach the settings file: %s", data)
	}
}
