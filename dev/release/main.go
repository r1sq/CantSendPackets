// Command release signs releases. It uses only the standard library, because it
// handles the key every installed copy of the app trusts.
//
//	go run ./dev/release keygen PRIVATE_KEY_FILE
//	go run ./dev/release sign VERSION DIR       (key in $RELEASE_SIGNING_KEY)
//
// keygen writes the private key to a file and the public key into the source tree.
// It never prints the private key.
//
// sign writes release.json and SHA256SUMS for every file in DIR, signs the manifest,
// and checks the signature against the key built into the app, so a mismatched
// secret fails the release rather than shipping one no installed copy would accept.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/r1sq/CantSendPackets/internal/update"
)

const publicKeyFile = "internal/update/release_key.pub"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: release keygen FILE | release sign VERSION DIR")
	}
	switch {
	case os.Args[1] == "keygen" && len(os.Args) == 3:
		keygen(os.Args[2])
	case os.Args[1] == "sign" && len(os.Args) == 4:
		sign(os.Args[2], os.Args[3])
	default:
		log.Fatal("usage: release keygen FILE | release sign VERSION DIR")
	}
}

func keygen(privateFile string) {
	if update.PublicKey() != nil {
		log.Fatalf("%s already holds a key. Replacing it means installed copies stop accepting updates, so remove it by hand if that's really intended.", publicKeyFile)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	seed := base64.StdEncoding.EncodeToString(priv.Seed())
	// O_EXCL: never overwrite an existing key.
	f, err := os.OpenFile(privateFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := f.WriteString(seed + "\n"); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(publicKeyFile, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Private key: %s\nPublic key:  %s (commit this)\n", privateFile, publicKeyFile)
	fmt.Println("Add the private key file's contents to GitHub as the secret RELEASE_SIGNING_KEY, and keep a copy somewhere safe.")
}

func sign(version, dir string) {
	if _, ok := update.ParseVersion(version); !ok {
		log.Fatalf("%q isn't a vX.Y.Z version", version)
	}
	public := update.PublicKey()
	if public == nil {
		log.Fatalf("%s is empty. Run keygen first.", publicKeyFile)
	}
	raw := strings.TrimSpace(os.Getenv("RELEASE_SIGNING_KEY"))
	seed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(seed) != ed25519.SeedSize {
		log.Fatal("RELEASE_SIGNING_KEY isn't set to a valid key")
	}
	private := ed25519.NewKeyFromSeed(seed)

	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	files := map[string]string{}
	var names []string
	for _, e := range entries {
		if e.IsDir() || e.Name() == update.ManifestName || e.Name() == update.SignatureName || e.Name() == "SHA256SUMS" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			log.Fatal(err)
		}
		sum := sha256.Sum256(data)
		files[e.Name()] = hex.EncodeToString(sum[:])
		names = append(names, e.Name())
	}
	if len(files) == 0 {
		log.Fatalf("nothing to sign in %s", dir)
	}
	manifest, err := json.MarshalIndent(update.Manifest{Version: version, Files: files}, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	signature := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, manifest)) + "\n")

	// Verified as the app would, through the app's own code and key.
	if _, err := update.VerifyManifest(manifest, signature, public); err != nil {
		log.Fatalf("RELEASE_SIGNING_KEY doesn't match %s: installed copies would refuse this release", publicKeyFile)
	}

	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	write(update.ManifestName, manifest)
	write(update.SignatureName, signature)

	sort.Strings(names)
	var sums strings.Builder
	for _, n := range names {
		fmt.Fprintf(&sums, "%s  %s\n", files[n], n)
	}
	write("SHA256SUMS", []byte(sums.String()))
	fmt.Printf("Signed %s: %d files\n", version, len(names))
}
