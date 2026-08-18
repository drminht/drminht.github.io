#!/usr/bin/env python3
"""Independent Stremio tvOS CDN scanner for the personal update manifest.

The scanner never republishes an IPA. It only discovers and verifies metadata for
plain tvOS IPA files hosted on Stremio's official dl.strem.io CDN.

Discovery is intentionally redundant:
1. derive plausible future semver/build combinations locally;
2. use Stremio's own AltStore source as an authoritative release-name hint;
3. use gorlev's community source only as an optional extra hint;
4. treat the actual dl.strem.io IPA + its Info.plist as the final authority.
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import json
from pathlib import Path
import plistlib
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "latest-tvos.json"
OFFICIAL_HOST = "dl.strem.io"
OFFICIAL_SOURCE = "https://dl.strem.io/apple/altstore/source.json"
GORLEV_SOURCE = "https://gorlev.github.io/stremio-altstore/stremio-tvos.json"
BUNDLE_ID = "com.stremio.pal"
USER_AGENT = "drminht-stremio-source/1.1"
BUILD_LOOKAHEAD = 8
PATCH_LOOKAHEAD = 4
VERSION_RE = re.compile(r"^(\d+\.\d+\.\d+)$")


def load_manifest() -> dict:
    with MANIFEST.open("r", encoding="utf-8") as f:
        return json.load(f)


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", value))


def valid_semver(value: str) -> bool:
    return bool(VERSION_RE.fullmatch(value))


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


def fetch_json(url: str) -> dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            if not 200 <= response.status < 300:
                return None
            value = json.load(response)
            return value if isinstance(value, dict) else None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return None


def head_exists(url: str) -> bool:
    if not is_official_tvos_url(url):
        return False
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            return 200 <= response.status < 400
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def next_semver_candidates(current_version: str) -> set[str]:
    """Derive future labels without assuming patch number == build delta."""
    if not valid_semver(current_version):
        return set()
    major, minor, patch = (int(part) for part in current_version.split("."))
    candidates = {current_version}
    for delta in range(1, PATCH_LOOKAHEAD + 1):
        candidates.add(f"{major}.{minor}.{patch + delta}")
    candidates.add(f"{major}.{minor + 1}.0")
    candidates.add(f"{major}.{minor + 1}.1")
    candidates.add(f"{major + 1}.0.0")
    return candidates


def official_source_hints(current_build: int) -> set[tuple[str, int]]:
    """Read version/build names advertised by Stremio itself.

    The official source's artifact format is not used here; only version/build names
    are consumed. Actual candidate URLs are reconstructed locally on dl.strem.io and
    verified against the downloaded IPA.
    """
    root = fetch_json(OFFICIAL_SOURCE)
    if not root:
        return set()

    hints: set[tuple[str, int]] = set()
    for app in root.get("apps", []):
        if not isinstance(app, dict):
            continue
        for item in app.get("versions", []):
            if not isinstance(item, dict):
                continue
            try:
                version = str(item["version"])
                build = int(item["buildVersion"])
            except (KeyError, TypeError, ValueError):
                continue
            if valid_semver(version) and build > current_build:
                hints.add((version, build))
    return hints


def gorlev_hints(current_build: int) -> set[tuple[str, int]]:
    """Use the community source only as an optional independent hint."""
    root = fetch_json(GORLEV_SOURCE)
    if not root:
        return set()

    hints: set[tuple[str, int]] = set()
    for app in root.get("apps", []):
        if not isinstance(app, dict) or app.get("bundleIdentifier") != BUNDLE_ID:
            continue
        for item in app.get("versions", []):
            if not isinstance(item, dict):
                continue
            try:
                version = str(item["version"])
                build = int(item["buildVersion"])
                url = str(item["downloadURL"])
            except (KeyError, TypeError, ValueError):
                continue
            if (
                valid_semver(version)
                and build > current_build
                and is_official_tvos_url(url)
            ):
                hints.add((version, build))
    return hints


def independent_candidates(current_version: str, current_build: int) -> set[tuple[str, int]]:
    """Generate a bounded local scan window independent of both external hint feeds."""
    semvers = next_semver_candidates(current_version)
    builds = range(current_build + 1, current_build + BUILD_LOOKAHEAD + 1)
    return {(version, build) for version in semvers for build in builds}


def inspect_ipa(url: str, expected_version: str, expected_build: int) -> dict:
    if not is_official_tvos_url(url):
        raise RuntimeError("refusing non-Stremio or non-tvOS URL")

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    sha = hashlib.sha256()

    with tempfile.NamedTemporaryFile(suffix=".ipa", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            with urllib.request.urlopen(req, timeout=90) as response:
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
        if size < 5_000_000:
            raise RuntimeError(f"IPA unexpectedly small: {size} bytes")

        with zipfile.ZipFile(tmp_path) as zf:
            plist_names = [
                name
                for name in zf.namelist()
                if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)
            ]
            if len(plist_names) != 1:
                raise RuntimeError(
                    f"expected one main app Info.plist, found {len(plist_names)}"
                )
            info = plistlib.loads(zf.read(plist_names[0]))

        bundle = str(info.get("CFBundleIdentifier", ""))
        version = str(info.get("CFBundleShortVersionString", ""))
        build = str(info.get("CFBundleVersion", ""))

        if bundle != BUNDLE_ID:
            raise RuntimeError(f"bundle mismatch: {bundle!r}")
        if version != expected_version:
            raise RuntimeError(
                f"version mismatch: expected {expected_version}, found {version}"
            )
        if build != str(expected_build):
            raise RuntimeError(
                f"build mismatch: expected {expected_build}, found {build}"
            )

        return {
            "version": version,
            "build": build,
            "downloadURL": url,
            "size": size,
            "sha256": sha.hexdigest(),
        }
    finally:
        tmp_path.unlink(missing_ok=True)


def write_verified(manifest: dict, verified: dict) -> None:
    manifest["latest"] = verified
    manifest["bootstrap"] = False
    manifest["verifiedAt"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    manifest = load_manifest()
    latest = manifest["latest"]
    current_version = str(latest["version"])
    current_build = int(latest["build"])
    current_url = str(latest["downloadURL"])

    if not valid_semver(current_version):
        raise SystemExit("current manifest version is not valid semantic versioning")
    if not is_official_tvos_url(current_url):
        raise SystemExit("current manifest URL is not an official Stremio tvOS IPA")
    if not head_exists(current_url):
        raise SystemExit("current Stremio tvOS IPA failed the CDN health check")

    local = independent_candidates(current_version, current_build)
    official = official_source_hints(current_build)
    community = gorlev_hints(current_build)
    candidates = local | official | community

    print(
        "Discovery candidates: "
        f"local={len(local)}, official-hints={len(official)}, "
        f"community-hints={len(community)}"
    )

    probe_targets = [
        (version, build, official_url(version, build))
        for version, build in candidates
        if build > current_build
    ]

    found: list[tuple[str, int, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
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

    found.sort(key=lambda item: (item[1], version_tuple(item[0])), reverse=True)

    # A successful HEAD is discovery only. The IPA's own Info.plist is authority.
    for version, build, url in found:
        try:
            verified = inspect_ipa(url, version, build)
        except Exception as exc:
            print(f"Rejected candidate {version} build {build}: {exc}")
            continue

        write_verified(manifest, verified)
        evidence = []
        if (version, build) in official:
            evidence.append("Stremio official source hint")
        if (version, build) in local:
            evidence.append("independent derived scan")
        if (version, build) in community:
            evidence.append("gorlev hint")
        print(
            f"Discovered and verified Stremio tvOS {version} build {build}; "
            f"evidence={', '.join(evidence) or 'CDN probe'}"
        )
        return 0

    # Bootstrap is the only time the current artifact is downloaded again solely to
    # establish a trusted local hash. Normal no-update runs use a lightweight HEAD.
    if manifest.get("bootstrap", False):
        verified = inspect_ipa(current_url, current_version, current_build)
        write_verified(manifest, verified)
        print(
            f"Bootstrap artifact independently verified: "
            f"{current_version} build {current_build}"
        )
    else:
        print(f"No newer build found; current is {current_version} build {current_build}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
