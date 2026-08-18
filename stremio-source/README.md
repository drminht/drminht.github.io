# Personal Stremio tvOS source

This directory publishes a small machine-readable manifest used by the private Stremio Refresh menu app.

The scheduled GitHub Actions scanner runs every six hours. It probes Stremio's official `dl.strem.io` CDN independently, uses the community AltStore source only as an optional discovery hint, and never republishes an IPA.

Before publishing a newly discovered build, the scanner downloads the official Stremio tvOS IPA and verifies:

- HTTPS + `dl.strem.io` host
- tvOS IPA path
- `CFBundleIdentifier == com.stremio.pal`
- `CFBundleShortVersionString`
- `CFBundleVersion`
- file size
- SHA-256

`latest-tvos.json` is the public manifest consumed by Stremio Refresh. The actual IPA always comes directly from Stremio's CDN.
