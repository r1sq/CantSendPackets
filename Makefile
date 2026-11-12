# Building needs only the Go toolchain: no npm, no cgo, no Wails CLI.
FLAGS := -trimpath -ldflags "-s -w"
GUI   := -trimpath -tags desktop,production -ldflags "-s -w -H windowsgui"
export CGO_ENABLED := 0

.PHONY: all test windows arm64 linux linux-gui netlab preview screenshots resources release release-linux-gui tag
all: test windows linux

test:
	GOOS=linux go vet ./cmd/... ./internal/... ./dev/...
	GOOS=windows go vet -tags desktop,production . ./cmd/... ./internal/... ./dev/...
	go test ./internal/...

windows:
	GOOS=windows GOARCH=amd64 go build $(GUI) -o build/CantSendPackets.exe .
	GOOS=windows GOARCH=amd64 go build $(FLAGS) -o build/cspcheck.exe ./cmd/cspcheck

arm64:
	GOOS=windows GOARCH=arm64 go build $(GUI) -o build/CantSendPackets-arm64.exe .

# cspcheck for Linux: static, so one file runs on any distribution.
linux:
	GOOS=linux GOARCH=amd64 go build $(FLAGS) -o build/cspcheck-linux-amd64 ./cmd/cspcheck
	GOOS=linux GOARCH=arm64 go build $(FLAGS) -o build/cspcheck-linux-arm64 ./cmd/cspcheck

# The Linux window, for this machine's architecture. Unlike everything else it
# needs cgo, a C compiler and the GTK 3 and WebKitGTK 4.1 development packages
# (Debian/Ubuntu: libgtk-3-dev libwebkit2gtk-4.1-dev).
LINUX_GUI_TAGS := desktop,production,webkit2_41
linux-gui:
	CGO_ENABLED=1 go build -trimpath -tags $(LINUX_GUI_TAGS) -ldflags "-s -w" -o build/CantSendPackets-linux-$(shell go env GOARCH) .

# The Linux checks against a simulated network in namespaces: rogue DHCP, a real
# loop, storms, discovery and a speed test. Needs Linux with user namespaces.
netlab:
	dev/netlab/netlab.sh

# The version the source is at. Every change bumps it; see CHANGELOG.md.
SOURCE_VERSION := v$(shell cat VERSION)

# Everything a GitHub release contains, signed. Needs VERSION=vX.Y.Z, equal to the
# VERSION file, and the key in $$RELEASE_SIGNING_KEY. This is what the release workflow runs.
OUT := build/release
RELEASE_GUI = -trimpath -buildvcs=false -tags desktop,production -ldflags "-s -w -H windowsgui -X main.version=$(VERSION)"
RELEASE_CLI = -trimpath -buildvcs=false -ldflags "-s -w"
# The Linux windows are built first, each on its own architecture (see
# release-linux-gui), and must be in $(LINUX_GUI_DIR) when this runs.
LINUX_GUI_DIR := build/linux-gui
release:
	@test -n "$(VERSION)" || (echo "VERSION=vX.Y.Z is required" && exit 1)
	@test "$(VERSION)" = "$(SOURCE_VERSION)" || (echo "$(VERSION) doesn't match the VERSION file ($(SOURCE_VERSION))" && exit 1)
	@for arch in amd64 arm64; do test -f $(LINUX_GUI_DIR)/CantSendPackets-linux-$$arch || { echo "missing $(LINUX_GUI_DIR)/CantSendPackets-linux-$$arch; run release-linux-gui first"; exit 1; }; done
	rm -rf $(OUT) && mkdir -p $(OUT)
	cp $(LINUX_GUI_DIR)/CantSendPackets-linux-amd64 $(LINUX_GUI_DIR)/CantSendPackets-linux-arm64 $(OUT)/
	GOOS=windows GOARCH=amd64 go build $(RELEASE_GUI) -o $(OUT)/CantSendPackets-windows-amd64.exe .
	GOOS=windows GOARCH=arm64 go build $(RELEASE_GUI) -o $(OUT)/CantSendPackets-windows-arm64.exe .
	GOOS=windows GOARCH=amd64 go build $(RELEASE_CLI) -o $(OUT)/cspcheck-windows-amd64.exe ./cmd/cspcheck
	GOOS=linux GOARCH=amd64 go build $(RELEASE_CLI) -o $(OUT)/cspcheck-linux-amd64 ./cmd/cspcheck
	GOOS=linux GOARCH=arm64 go build $(RELEASE_CLI) -o $(OUT)/cspcheck-linux-arm64 ./cmd/cspcheck
	go run ./dev/release sign $(VERSION) $(OUT)

# One release's Linux window, for this machine's architecture. Built on the oldest
# distribution supported, since the result needs at least its glibc.
release-linux-gui:
	@test -n "$(VERSION)" || (echo "VERSION=vX.Y.Z is required" && exit 1)
	@test "$(VERSION)" = "$(SOURCE_VERSION)" || (echo "$(VERSION) doesn't match the VERSION file ($(SOURCE_VERSION))" && exit 1)
	mkdir -p $(LINUX_GUI_DIR)
	CGO_ENABLED=1 go build -trimpath -buildvcs=false -tags $(LINUX_GUI_TAGS) -ldflags "-s -w -X main.version=$(VERSION)" -o $(LINUX_GUI_DIR)/CantSendPackets-linux-$(shell go env GOARCH) .

# Serves the UI with mock data; prints the URL. Scenarios: see dev/preview/main.go.
preview:
	go run ./dev/preview

# Regenerates docs/screenshots from the preview. Needs Node 22+ and Chromium (CHROME=...).
screenshots:
	node dev/screenshots/shoot.mjs

# Regenerates the checked-in icon and manifest objects.
resources:
	go run ./dev/genres

# Tags HEAD with the VERSION file's version. Pushing the tag to origin publishes the release.
tag:
	@git diff --quiet HEAD || (echo "commit your changes first" && exit 1)
	@grep -q "^## \[$(shell cat VERSION)\]" CHANGELOG.md || (echo "CHANGELOG.md has no entry for $(SOURCE_VERSION)" && exit 1)
	git tag -a $(SOURCE_VERSION) -m $(SOURCE_VERSION)
	@echo "Publish with: git push origin $(SOURCE_VERSION)"
