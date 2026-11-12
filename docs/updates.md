# Updates

Release builds look for a newer release on GitHub 10 seconds after starting and then daily, through
the same proxy settings as everything else. This can be turned off in Settings. Installing always
takes a click: the file is downloaded, verified and swapped in, and the app restarts. Builds that
aren't releases (their version ends in `-dev`) never update themselves.

The app can only replace itself in a folder its user can write to. In Program Files it says so and
leaves things as they are.

## Why an update can be trusted

A self-updater runs what it downloads, so each release has a manifest, `release.json`, listing its
version and every file's SHA-256, signed with Ed25519. The public key is built into the app. A
changed file, another key, or an old release republished under a new tag are all refused.

The signing key lives in GitHub as a secret of the `release` environment, so someone with admin
access to the repository could still publish a signed release. Required reviewers on that
environment make publishing take a second approval.

To check a download by hand, compare its SHA-256 with `SHA256SUMS` or `release.json` in the release.
