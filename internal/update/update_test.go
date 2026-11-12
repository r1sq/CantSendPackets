package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

const asset = "CantSendPackets-windows-amd64.exe"

var exeBytes = []byte("MZ pretend this is a new program")

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fakeGitHub holds one published release, with knobs for each way it can be wrong.
type fakeGitHub struct {
	tag         string
	manifest    Manifest
	key         ed25519.PrivateKey
	exe         []byte
	badSig      bool
	apiErr      error
	assetPrefix string
	omit        string
	draft       bool
	prerelease  bool
	fetched     []string
}

func newFake(t *testing.T, tag string, key ed25519.PrivateKey) *fakeGitHub {
	return &fakeGitHub{
		tag: tag, key: key, exe: exeBytes, assetPrefix: downloadPrefix + tag + "/",
		manifest: Manifest{Version: tag, Files: map[string]string{asset: hash(exeBytes)}},
	}
}

func (f *fakeGitHub) Get(_ context.Context, u string, max int64) ([]byte, error) {
	f.fetched = append(f.fetched, u)
	if u == apiURL {
		if f.apiErr != nil {
			return nil, f.apiErr
		}
		rel := githubRelease{TagName: f.tag, Draft: f.draft, Prerelease: f.prerelease}
		for _, name := range []string{ManifestName, SignatureName, asset} {
			if name != f.omit {
				rel.Assets = append(rel.Assets, struct {
					Name string `json:"name"`
					URL  string `json:"browser_download_url"`
				}{name, f.assetPrefix + name})
			}
		}
		return json.Marshal(rel)
	}
	manifest, _ := json.Marshal(f.manifest)
	switch {
	case strings.HasSuffix(u, "/"+ManifestName):
		return manifest, nil
	case strings.HasSuffix(u, "/"+SignatureName):
		sig := ed25519.Sign(f.key, manifest)
		if f.badSig {
			sig[0] ^= 0xff
		}
		return []byte(base64.StdEncoding.EncodeToString(sig)), nil
	case strings.HasSuffix(u, "/"+asset):
		return f.exe, nil
	}
	return nil, fmt.Errorf("unexpected URL %s", u)
}

func errKey(err error) string { return verdict.AsMsg(err).Key }

func TestVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.2.0", "v0.1.0", true},
		{"v0.1.0", "v0.2.0", false},
		{"v0.1.0", "v0.1.0", false},
		{"v1.0.0", "v0.99.99", true},
		{"v0.10.0", "v0.9.0", true}, // numeric, not alphabetical
		{"v0.1.10", "v0.1.9", true},
		{"v1.0.0-rc1", "v0.1.0", false},
		{"1.0.0", "v0.1.0", false},
		{"v1.0", "v0.1.0", false},
		{"latest", "v0.1.0", false},
		{"v1.0.0", "dev", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestFindsAndVerifiesANewerRelease(t *testing.T) {
	pub, priv := newKey(t)
	f := newFake(t, "v0.2.0", priv)
	a, err := Check(context.Background(), f, "v0.1.0", asset, pub)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil || a.Version != "v0.2.0" || !strings.HasSuffix(a.PageURL, "/releases/tag/v0.2.0") {
		t.Fatalf("%+v", a)
	}
	data, err := Download(context.Background(), f, a)
	if err != nil || string(data) != string(exeBytes) {
		t.Errorf("%q %v", data, err)
	}
}

func TestNothingToDo(t *testing.T) {
	pub, priv := newKey(t)
	cases := map[string]func(*fakeGitHub){
		"same version":  func(f *fakeGitHub) { f.tag = "v0.1.0" },
		"older version": func(f *fakeGitHub) { f.tag = "v0.0.9" },
		"draft":         func(f *fakeGitHub) { f.draft = true },
		"pre-release":   func(f *fakeGitHub) { f.prerelease = true },
		"odd tag":       func(f *fakeGitHub) { f.tag = "nightly" },
		"no release":    func(f *fakeGitHub) { f.apiErr = ErrNotFound },
	}
	for name, change := range cases {
		f := newFake(t, "v0.2.0", priv)
		change(f)
		a, err := Check(context.Background(), f, "v0.1.0", asset, pub)
		if a != nil || err != nil {
			t.Errorf("%s: %+v %v", name, a, err)
		}
	}
}

// Each of these is what an attacker holding the GitHub account, but not the signing
// key, could try. None may ever produce something installable.
func TestRejects(t *testing.T) {
	pub, priv := newKey(t)
	_, otherKey := newKey(t)
	cases := []struct {
		name   string
		change func(*fakeGitHub)
		want   string
	}{
		{"flipped signature", func(f *fakeGitHub) { f.badSig = true }, "err.update.badSignature"},
		{"signed with another key", func(f *fakeGitHub) { f.key = otherKey }, "err.update.badSignature"},
		{"old signed release under a new tag", func(f *fakeGitHub) { f.manifest.Version = "v0.0.1" }, "err.update.badSignature"},
		{"missing signature", func(f *fakeGitHub) { f.omit = SignatureName }, "err.update.incomplete"},
		{"missing manifest", func(f *fakeGitHub) { f.omit = ManifestName }, "err.update.incomplete"},
		{"missing program", func(f *fakeGitHub) { f.omit = asset }, "err.update.incomplete"},
		{"hash missing from the manifest", func(f *fakeGitHub) { f.manifest.Files = map[string]string{} }, "err.update.incomplete"},
		{"files hosted elsewhere", func(f *fakeGitHub) { f.assetPrefix = "https://evil.example/" }, "err.update.incomplete"},
		{"another repo's release", func(f *fakeGitHub) { f.assetPrefix = "https://github.com/evil/repo/releases/download/v0.2.0/" }, "err.update.incomplete"},
	}
	for _, c := range cases {
		f := newFake(t, "v0.2.0", priv)
		c.change(f)
		a, err := Check(context.Background(), f, "v0.1.0", asset, pub)
		if a != nil {
			t.Errorf("%s: accepted %+v", c.name, a)
		}
		if errKey(err) != c.want {
			t.Errorf("%s: %v, want %s", c.name, err, c.want)
		}
	}
}

func TestTamperedProgramIsRejected(t *testing.T) {
	pub, priv := newKey(t)
	f := newFake(t, "v0.2.0", priv)
	a, err := Check(context.Background(), f, "v0.1.0", asset, pub)
	if err != nil {
		t.Fatal(err)
	}
	f.exe = []byte("MZ something else entirely")
	if data, err := Download(context.Background(), f, a); data != nil || errKey(err) != "err.update.badHash" {
		t.Errorf("%q %v", data, err)
	}
}

func TestBuildsThatMustNotUpdate(t *testing.T) {
	pub, priv := newKey(t)
	f := newFake(t, "v0.2.0", priv)
	if _, err := Check(context.Background(), f, "dev", asset, pub); errKey(err) != "err.update.devBuild" {
		t.Errorf("%v", err)
	}
	if _, err := Check(context.Background(), f, "v0.1.0", asset, nil); errKey(err) != "err.update.noKey" {
		t.Errorf("%v", err)
	}
	if len(f.fetched) != 0 {
		t.Errorf("shouldn't have contacted anything: %v", f.fetched)
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _ := newKey(t)
	if got := ParsePublicKey(" " + base64.StdEncoding.EncodeToString(pub) + "\n"); !got.Equal(pub) {
		t.Error("valid key refused")
	}
	for _, bad := range []string{"", "not base64!", "c2hvcnQ="} {
		if ParsePublicKey(bad) != nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestInstallReplacesTheProgram(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "app.exe")
	os.WriteFile(exe, []byte("old"), 0o755)

	rollback, err := Install(exe, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "new" {
		t.Errorf("%q", got)
	}
	if got, _ := os.ReadFile(exe + ".old"); string(got) != "old" {
		t.Errorf("old copy: %q", got)
	}
	if _, err := os.Stat(exe + ".new"); err == nil {
		t.Error("temporary file left behind")
	}

	if err := rollback(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old" {
		t.Errorf("after rollback: %q", got)
	}
}

func TestInstallOverALeftoverFromLastTime(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "app.exe")
	os.WriteFile(exe, []byte("current"), 0o755)
	os.WriteFile(exe+".old", []byte("ancient"), 0o755)
	os.WriteFile(exe+".new", []byte("partial"), 0o755)
	if _, err := Install(exe, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(exe + ".old"); string(got) != "current" {
		t.Errorf("%q", got)
	}
}

func TestInstallFailureLeavesTheAppInPlace(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "missing", "app.exe")
	if _, err := Install(exe, []byte("new")); err == nil {
		t.Fatal("no error")
	}
	real := filepath.Join(dir, "app.exe")
	os.WriteFile(real, []byte("current"), 0o755)
	os.Mkdir(real+".new", 0o755) // can't be written as a file
	if _, err := Install(real, []byte("new")); err == nil {
		t.Fatal("no error")
	}
	if got, _ := os.ReadFile(real); string(got) != "current" {
		t.Errorf("the app was damaged: %q", got)
	}
}

func TestCleanup(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "app.exe")
	os.WriteFile(exe, []byte("x"), 0o755)
	os.WriteFile(exe+".old", []byte("x"), 0o755)
	Cleanup(exe)
	if _, err := os.Stat(exe + ".old"); err == nil {
		t.Error("old copy remains")
	}
	if _, err := os.Stat(exe); err != nil {
		t.Error("removed the app itself")
	}
}

func tlsServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, HTTPOptions) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	pool := s.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return s, HTTPOptions{RootCAs: pool}
}

func TestHTTPGet(t *testing.T) {
	ctx := context.Background()
	s, opt := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			if r.Header.Get("User-Agent") == "" {
				t.Error("GitHub refuses requests with no User-Agent")
			}
			w.Write([]byte("hello"))
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/downgrade":
			http.Redirect(w, r, "http://example.invalid/x", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/limited":
			w.WriteHeader(http.StatusForbidden)
		case "/big":
			w.Write(make([]byte, 100))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	if got, err := HTTPGet(ctx, s.URL+"/ok", opt, 100); err != nil || string(got) != "hello" {
		t.Errorf("%q %v", got, err)
	}
	if got, err := HTTPGet(ctx, s.URL+"/redirect", opt, 100); err != nil || string(got) != "hello" {
		t.Errorf("redirect: %q %v", got, err)
	}
	if _, err := HTTPGet(ctx, s.URL+"/downgrade", opt, 100); err == nil {
		t.Error("followed a redirect out of HTTPS")
	}
	if _, err := HTTPGet(ctx, s.URL+"/loop", opt, 100); err == nil {
		t.Error("redirect loop")
	}
	if _, err := HTTPGet(ctx, s.URL+"/none", opt, 100); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: %v", err)
	}
	if _, err := HTTPGet(ctx, s.URL+"/limited", opt, 100); errKey(err) != "err.update.rateLimited" {
		t.Errorf("403: %v", err)
	}
	if _, err := HTTPGet(ctx, s.URL+"/big", opt, 10); errKey(err) != "err.update.tooLarge" {
		t.Errorf("limit: %v", err)
	}
	if _, err := HTTPGet(ctx, "http://example.invalid/", opt, 100); err == nil {
		t.Error("accepted plain HTTP")
	}
	if _, err := HTTPGet(ctx, s.URL+"/ok", HTTPOptions{}, 100); err == nil {
		t.Error("trusted an unknown certificate")
	}
}

func TestHTTPGetThroughAProxyWantingALogin(t *testing.T) {
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer p.Close()
	u, _ := url.Parse(p.URL)
	_, err := HTTPGet(context.Background(), "https://site.invalid/x", HTTPOptions{Proxy: u}, 100)
	if !errors.Is(err, ErrProxyAuth) {
		t.Errorf("%v", err)
	}
}

func TestBuildVersion(t *testing.T) {
	cases := []struct{ source, stamped, want string }{
		{"0.4.1\n", "", "v0.4.1-dev"},
		{"0.4.1\n", "v0.4.1", "v0.4.1"},
		{"", "", "dev"},
	}
	for _, c := range cases {
		if got := BuildVersion(c.source, c.stamped); got != c.want {
			t.Errorf("BuildVersion(%q, %q) = %q, want %q", c.source, c.stamped, got, c.want)
		}
	}
	if _, ok := ParseVersion(BuildVersion("0.4.1", "")); ok {
		t.Error("a development build must not count as an updatable version")
	}
}

// The VERSION file at the repository root is what every build reports and what
// a release tag must match, so it has to stay a plain X.Y.Z.
func TestVersionFileIsSemver(t *testing.T) {
	b, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ParseVersion("v" + strings.TrimSpace(string(b))); !ok {
		t.Errorf("VERSION is %q, want X.Y.Z", b)
	}
}
