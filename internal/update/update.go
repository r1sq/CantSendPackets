// Package update finds, verifies and installs new releases from GitHub.
//
// A self-updater runs whatever it downloads, so nothing from the network is trusted
// until a signature says so. Each release carries release.json, listing its version
// and the SHA-256 of every file, and release.json.sig, an Ed25519 signature made
// with a key that isn't on GitHub's servers in plain form. The public half is built
// into the app. That catches a tampered file, and because the signed manifest names
// its version, it also catches an old release dressed up as a new one.
package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

const (
	// Repo is where releases come from.
	Repo = "r1sq/CantSendPackets"

	ManifestName  = "release.json"
	SignatureName = "release.json.sig"

	apiURL         = "https://api.github.com/repos/" + Repo + "/releases/latest"
	downloadPrefix = "https://github.com/" + Repo + "/releases/download/"
	pagePrefix     = "https://github.com/" + Repo + "/releases/tag/"

	maxAPIBytes      = 1 << 20
	maxManifestBytes = 64 << 10
	maxAssetBytes    = 64 << 20
)

//go:embed release_key.pub
var embeddedKey string

// PublicKey returns the key releases must be signed with, or nil if this build has
// none, in which case updates stay off rather than running unverified.
func PublicKey() ed25519.PublicKey {
	return ParsePublicKey(embeddedKey)
}

// ParsePublicKey decodes a base64 key, returning nil if it isn't one.
func ParsePublicKey(s string) ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return raw
}

// ErrNotFound means the URL doesn't exist, as with a repo that has no release yet.
var ErrNotFound = errors.New("not found")

// Fetcher downloads a URL, following redirects, failing if it exceeds max bytes.
type Fetcher interface {
	Get(ctx context.Context, url string, max int64) ([]byte, error)
}

// Manifest is the signed description of a release.
type Manifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"`
}

var versionPattern = regexp.MustCompile(`^v(\d{1,6})\.(\d{1,6})\.(\d{1,6})$`)

// ParseVersion reads a plain vX.Y.Z. Anything else, such as a pre-release suffix or
// a development build, isn't a version an update can compare against.
func ParseVersion(v string) ([3]int, bool) {
	m := versionPattern.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out, true
}

// BuildVersion is the version a build reports. A release build has its tag
// stamped in, which wins. Anything else is the source's version (the VERSION
// file) marked "-dev": it's shown, but ParseVersion rejects it, so a
// development build never updates itself.
func BuildVersion(source, stamped string) string {
	if stamped != "" {
		return stamped
	}
	v := strings.TrimSpace(source)
	if v == "" {
		return "dev"
	}
	return "v" + v + "-dev"
}

// Newer reports whether candidate is a later version than current.
func Newer(candidate, current string) bool {
	a, okA := ParseVersion(candidate)
	b, okB := ParseVersion(current)
	if !okA || !okB {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// Available is a verified newer release.
type Available struct {
	Version string `json:"version"`
	PageURL string `json:"pageUrl"`

	assetURL string
	sha256   string
}

type githubRelease struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Check looks for a newer release. It returns nil if there isn't one. Nothing is
// reported as available unless its signature has been verified.
func Check(ctx context.Context, f Fetcher, current, assetName string, key ed25519.PublicKey) (*Available, error) {
	if key == nil {
		return nil, verdict.Err("err.update.noKey")
	}
	if _, ok := ParseVersion(current); !ok {
		return nil, verdict.Err("err.update.devBuild")
	}
	body, err := f.Get(ctx, apiURL, maxAPIBytes)
	if errors.Is(err, ErrNotFound) {
		return nil, nil // no release published yet
	}
	if err != nil {
		return nil, err
	}
	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, verdict.Err("err.update.badResponse")
	}
	if rel.Draft || rel.Prerelease || !Newer(rel.TagName, current) {
		return nil, nil
	}

	urls := map[string]string{}
	for _, a := range rel.Assets {
		// Only this repo's download area. The signature would catch a foreign file
		// anyway, but there's no reason to fetch from anywhere else at all.
		if strings.HasPrefix(a.URL, downloadPrefix) {
			urls[a.Name] = a.URL
		}
	}
	if urls[ManifestName] == "" || urls[SignatureName] == "" || urls[assetName] == "" {
		return nil, verdict.Err("err.update.incomplete", "version", rel.TagName)
	}
	manifestBytes, err := f.Get(ctx, urls[ManifestName], maxManifestBytes)
	if err != nil {
		return nil, err
	}
	sigBytes, err := f.Get(ctx, urls[SignatureName], maxManifestBytes)
	if err != nil {
		return nil, err
	}
	manifest, err := VerifyManifest(manifestBytes, sigBytes, key)
	if err != nil {
		return nil, err
	}
	// The tag isn't signed, the manifest is. Without this, an old signed release
	// could be republished under a new tag to roll everyone back to a known bug.
	if manifest.Version != rel.TagName {
		return nil, verdict.Err("err.update.badSignature")
	}
	sum := manifest.Files[assetName]
	if len(sum) != sha256.Size*2 {
		return nil, verdict.Err("err.update.incomplete", "version", rel.TagName)
	}
	return &Available{Version: manifest.Version, PageURL: pagePrefix + manifest.Version, assetURL: urls[assetName], sha256: sum}, nil
}

// VerifyManifest checks a manifest's signature, and only then parses it.
func VerifyManifest(manifest, signature []byte, key ed25519.PublicKey) (Manifest, error) {
	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(signature)))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, manifest, sig) {
		return Manifest{}, verdict.Err("err.update.badSignature")
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return Manifest{}, verdict.Err("err.update.badSignature")
	}
	return m, nil
}

// Download fetches a release's file and checks it against the signed hash.
func Download(ctx context.Context, f Fetcher, a *Available) ([]byte, error) {
	data, err := f.Get(ctx, a.assetURL, maxAssetBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(a.sha256) {
		return nil, verdict.Err("err.update.badHash")
	}
	return data, nil
}
