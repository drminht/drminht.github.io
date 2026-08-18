#!/usr/bin/env python3
"""Independent Stremio tvOS CDN scanner for the personal update manifest.

The scanner never republishes an IPA. It only discovers and verifies metadata for
plain tvOS IPA files hosted on Stremio's official dl.strem.io CDN.
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import tempfile
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "latest-tvos.json"
OFFICIAL_HOST = "dl.strem.io"
BUNDLE_ID = "com.stremio.pal"
GORLEV_SOURCE = "https://gorlev.github.io/stremio-altstore/stremio-tvos.json"
USER_AGENT = "drminht-stremio-source/1.0"


def load_manifest() -> dict:
    with MANIFEST.open("r", encoding="utf-8") as f:
        return json.load(f)


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", value))


def official_url(version: str, build: int | str) -> str:
    return f"https://{OFFICIAL_HOST}/apple/{version}b{build}/tvos/stremio_tvOS.ipa"


def is_official_tvos_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == OFFICIAL_HOST
        and parsed.path.endswith("/tvos/stremio_tvOS.ipa")
    )


def head_exists(url: str) -> bool:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return 200 <= r.status < 400
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def gorlev_hints(current_build: int) -> set[tuple[str, int]]:
    """Use the community source only as an optional hint, never as authority."""
    req = urllib.request.Request(GORLEV_SOURCE, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            root = json.load(r)
    except Exception:
        return set()

    hints: set[tuple[str, int]] = set()
    for app in root.get("apps", []):
        if app.get("bundleIdentifier") != BUNDLE_ID:
            continue
        for item in app.get("versions", []):
            try:
                version = str(item["version"])
                build = int(item["buildVersion"])
                url = str(item["downloadURL"])
            except (KeyError, TypeError, ValueError):
                continue
            if build > current_build and is_official_tvos_url(url):
                hints.add((version, build))
    return hints


def independent_candidates(current_version: str, current_build: int) -> set[tuple[str, int]]:
    """Generate future version/build candidates without relying on the community source.

    The scanner probes a bounded forward window. It covers the current release line,
    the next two minor lines, and the next major line. Builds remain the monotonic
    anchor, while patch guesses are deliberately redundant to tolerate skipped labels.
    """
    parts = list(version_tuple(current_version))
    while len(parts) < 3:
        parts.append(0)
    major, minor, patch = parts[:3]

    candidates: set[tuple[str, int]] = set()
    offset = current_build - patch

    for build in range(current_build + 1, current_build + 25):
        expected_patch = max(0, build - offset)

        # Current minor line: expected patch plus a small tolerance window.
        for p in {expected_patch - 1, expected_patch, expected_patch + 1}:
            if p >= 0:
                candidates.add((f"{major}.{minor}.{p}", build))

        # Future minor lines may reset patch numbering.
        for future_minor in (minor + 1, minor + 2):
            for p in range(0, 7):
                candidates.add((f"{major}.{future_minor}.{p}", build))

        # Future major line, similarly allowing a small early patch range.
        for p in range(0, 5):
            candidates.add((f"{major + 1}.0.{p}", build))

    return candidates


def inspect_ipa(url: str, expected_version: str, expected_build: int) -> dict:
    if not is_official_tvos_url(url):
        raise RuntimeError("refusing non-Stremio or non-tvOS URL")

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    sha = hashlib.sha256()

    with tempfile.NamedTemporaryFile(suffix=".ipa", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    sha.update(chunk)
                    tmp.write(chunk)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

    try:
        size = tmp_path.stat().st_size
        with zipfile.ZipFile(tmp_path) as zf:
            plist_names = [
                n
                for n in zf.namelist()
                if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)
            ]
            if len(plist_names) != 1:
                raise RuntimeError(f"expected one main app Info.plist, found {len(plist_names)}")
            info = plistlib.loads(zf.read(plist_names[0]))

        bundle = str(info.get("CFBundleIdentifier", ""))
        version = str(info.get("CFBundleShortVersionString", ""))
        build = str(info.get("CFBundleVersion", ""))

        if bundle != BUNDLE_ID:
            raise RuntimeError(f"bundle mismatch: {bundle!r}")
        if version != expected_version:
            raise RuntimeError(f"version mismatch: expected {expected_version}, found {version}")
        if build != str(expected_build):
            raise RuntimeError(f"build mismatch: expected {expected_build}, found {build}")

        return {
            "version": version,
            "build": build,
            "downloadURL": url,
            "size": size,
            "sha256": sha.hexdigest(),
        }
    finally:
        tmp_path.unlink(missing_ok=True)


def main() -> int:
    manifest = load_manifest()
    latest = manifest["latest"]
    current_version = str(latest["version"])
    current_build = int(latest["build"])
    current_url = str(latest["downloadURL"])

    if not is_official_tvos_url(current_url):
        raise SystemExit("current manifest URL is not an official Stremio tvOS IPA")
    if not head_exists(current_url):
        raise SystemExit("current Stremio tvOS IPA failed the CDN health check")

    candidates = independent_candidates(current_version, current_build)
    candidates |= gorlev_hints(current_build)

    # Probe only future builds; the actual IPA is downloaded only for the newest hit.
    probe_targets = [
        (version, build, official_url(version, build))
        for version, build in candidates
        if build > current_build
    ]

    found: list[tuple[str, int, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        future_map = {
            pool.submit(head_exists, url): (version, build, url)
            for version, build, url in probe_targets
        }
        for future in concurrent.futures.as_completed(future_map):
            version, build, url = future_map[future]
            try:
                exists = future.result()
            except Exception:
                exists = False
            if exists:
                found.append((version, build, url))

    # Highest build wins; semantic version breaks ties.
    found.sort(key=lambda x: (x[1], version_tuple(x[0])), reverse=True)

    if found:
        version, build, url = found[0]
        verified = inspect_ipa(url, version, build)
        manifest["latest"] = verified
        manifest["bootstrap"] = False
        manifest["verifiedAt"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"Discovered and verified Stremio tvOS {version} build {build}")
        return 0

    # On the first run, independently verify the bootstrap artifact and hash.
    if manifest.get("bootstrap", False):
        verified = inspect_ipa(current_url, current_version, current_build)
        manifest["latest"] = verified
        manifest["bootstrap"] = False
        manifest["verifiedAt"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"Bootstrap artifact independently verified: {current_version} build {current_build}")
    else:
        print(f"No newer build found; current is {current_version} build {current_build}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
