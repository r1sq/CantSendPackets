// Package settings persists the app's options as a small JSON file. Proxy
// passwords are deliberately not part of it: they stay in memory for the session.
package settings

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/r1sq/CantSendPackets/internal/proxy"
)

// Settings is everything the user can configure.
type Settings struct {
	ProxyMode    proxy.OverrideMode `json:"proxyMode"`
	ProxyAddress string             `json:"proxyAddress"`
	ProxyBypass  string             `json:"proxyBypass"`
	PACURL       string             `json:"pacUrl"`
	// TrustedProxies are hosts the user approved for Windows logins.
	TrustedProxies []string `json:"trustedProxies"`
	// Discoverable announces this PC to other instances and accepts speed tests.
	Discoverable bool `json:"discoverable"`
	// CheckUpdates looks for new releases on GitHub. Installing always takes a click.
	CheckUpdates bool `json:"checkUpdates"`
}

// Default is the state before anything was changed.
func Default() Settings {
	return Settings{ProxyMode: proxy.OverrideAuto, TrustedProxies: []string{}, Discoverable: true, CheckUpdates: true}
}

// Override returns the proxy override these settings describe.
func (s Settings) Override() proxy.Override {
	return proxy.Override{Mode: s.ProxyMode, Address: s.ProxyAddress, Bypass: s.ProxyBypass, PACURL: s.PACURL}
}

// Path returns the settings file for this user.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "CantSendPackets", "settings.json"), nil
}

// Load reads settings. A missing file gives the defaults. So does an unusable
// one, with an error so the caller can say so; the app must still start.
func Load(path string) (Settings, error) {
	s := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return Default(), err
	}
	if m := proxy.CheckOverride(s.Override()); !m.IsZero() {
		return Default(), errors.New(m.String())
	}
	if s.TrustedProxies == nil {
		s.TrustedProxies = []string{}
	}
	return s, nil
}

// Save writes settings via a temporary file, so a crash can't leave half a file.
func Save(path string, s Settings) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "settings-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
