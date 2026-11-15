# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Mobile quality auditing: Android APK inspection and PWA installability.

APK checks are static: the file is read as a ZIP container, so no emulator,
SDK, or device is required and the audit stays deterministic. PWA checks take
an already-fetched HTML document, web app manifest, and service worker, which
keeps the entire matrix unit-testable offline; :func:`fetch_pwa` is the thin
live layer.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import httpx

from qa_agent.models import Finding, Severity
from qa_agent.redaction import redact_text, redact_url

__all__ = [
    "ApkReport",
    "DANGEROUS_PERMISSIONS",
    "PwaReport",
    "analyze_apk_manifest",
    "audit_pwa",
    "audit_pwa_dir",
    "fetch_pwa",
    "inspect_apk",
    "manifest_icon_sizes",
]


DANGEROUS_PERMISSIONS: Mapping[str, Severity] = {
    "android.permission.READ_SMS": Severity.CRITICAL,
    "android.permission.RECEIVE_SMS": Severity.CRITICAL,
    "android.permission.SEND_SMS": Severity.HIGH,
    "android.permission.READ_CALL_LOG": Severity.CRITICAL,
    "android.permission.WRITE_CALL_LOG": Severity.CRITICAL,
    "android.permission.CALL_PHONE": Severity.HIGH,
    "android.permission.READ_CONTACTS": Severity.HIGH,
    "android.permission.WRITE_CONTACTS": Severity.HIGH,
    "android.permission.ACCESS_FINE_LOCATION": Severity.HIGH,
    "android.permission.ACCESS_BACKGROUND_LOCATION": Severity.CRITICAL,
    "android.permission.RECORD_AUDIO": Severity.MEDIUM,
    "android.permission.CAMERA": Severity.MEDIUM,
    "android.permission.READ_EXTERNAL_STORAGE": Severity.MEDIUM,
    "android.permission.WRITE_EXTERNAL_STORAGE": Severity.MEDIUM,
    "android.permission.REQUEST_INSTALL_PACKAGES": Severity.CRITICAL,
    "android.permission.SYSTEM_ALERT_WINDOW": Severity.HIGH,
    "android.permission.PACKAGE_USAGE_STATS": Severity.HIGH,
}

_PACKAGE_RE = re.compile(r'\bpackage\s*=\s*"([^"]+)"')
_VERSION_RE = re.compile(r'android:versionName\s*=\s*"([^"]+)"')
_VERSION_CODE_RE = re.compile(r'android:versionCode\s*=\s*"([^"]+)"')
_SDK_RE = re.compile(r'android:(?:min|target)SdkVersion\s*=\s*"(\d+)"')
_PERMISSION_RE = re.compile(r'<uses-permission[^>]*android:name\s*=\s*"([^"]+)"')
_COMPONENT_RE = re.compile(r"<(activity|service|receiver|provider)\b([^>]*)>", re.IGNORECASE)


def _finding(
    title: str,
    severity: Severity,
    category: str,
    description: str,
    evidence: str = "",
    recommendation: str = "",
    url: str = "",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=description,
        url=redact_url(url) if url else "",
        evidence=redact_text(evidence),
        recommendation=recommendation,
    )


@dataclass
class ApkReport:
    path: str
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: tuple[str, ...] = ()
    components: tuple[tuple[str, str], ...] = ()
    signed: bool = False
    debug_build: bool = False
    allow_backup: bool = True
    cleartext_traffic: bool = True
    dex_count: int = 0
    native_abis: tuple[str, ...] = ()
    manifest_binary: bool = False
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": redact_url(self.path),
            "package": self.package,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "permissions": list(self.permissions),
            "components": [list(item) for item in self.components],
            "signed": self.signed,
            "debug_build": self.debug_build,
            "allow_backup": self.allow_backup,
            "cleartext_traffic": self.cleartext_traffic,
            "dex_count": self.dex_count,
            "native_abis": list(self.native_abis),
            "manifest_binary": self.manifest_binary,
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def analyze_apk_manifest(manifest: str) -> dict[str, Any]:
    """Extract package facts from a plain-text AndroidManifest.xml string."""
    text = manifest or ""
    sdk_values = [int(value) for value in _SDK_RE.findall(text)]
    components: list[tuple[str, str]] = []
    exported_without_permission = False
    for tag, attributes in _COMPONENT_RE.findall(text):
        name = re.search(r'android:name\s*=\s*"([^"]+)"', attributes)
        exported = 'android:exported="true"' in attributes
        permission = "android:permission=" in attributes
        if exported and not permission:
            exported_without_permission = True
        components.append((tag.lower(), name.group(1) if name else ""))
    return {
        "package": (_PACKAGE_RE.search(text).group(1) if _PACKAGE_RE.search(text) else ""),
        "version_name": (_VERSION_RE.search(text).group(1) if _VERSION_RE.search(text) else ""),
        "version_code": (_VERSION_CODE_RE.search(text).group(1) if _VERSION_CODE_RE.search(text) else ""),
        "min_sdk": min(sdk_values) if sdk_values else 0,
        "target_sdk": max(sdk_values) if sdk_values else 0,
        "permissions": tuple(sorted(set(_PERMISSION_RE.findall(text)))),
        "components": tuple(components),
        "exported_without_permission": exported_without_permission,
        "debuggable": 'android:debuggable="true"' in text,
        "allow_backup": 'android:allowBackup="true"' in text,
        "cleartext": 'android:usesCleartextTraffic="true"' in text,
        "network_security_config": "networkSecurityConfig" in text,
    }


def inspect_apk(path: str | Path, *, url: str = "") -> ApkReport:
    """Statically audit an APK container without an Android SDK."""
    target = Path(path)
    report = ApkReport(path=str(target))
    if not target.is_file():
        report.findings.append(
            _finding(
                "APK not found",
                Severity.HIGH,
                "mobile-apk-missing",
                "The APK path does not exist, so no mobile checks could run.",
                str(target),
                "Build the release APK and re-run the audit.",
            )
        )
        return report
    try:
        with zipfile.ZipFile(target) as archive:
            names = archive.namelist()
            report.dex_count = sum(1 for name in names if name.endswith(".dex"))
            report.native_abis = tuple(
                sorted({name.split("/")[1] for name in names if name.startswith("lib/") and name.count("/") >= 2})
            )
            report.signed = any(
                name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC")) for name in names
            )
            if "AndroidManifest.xml" not in names:
                report.findings.append(
                    _finding(
                        "APK has no AndroidManifest.xml",
                        Severity.CRITICAL,
                        "mobile-apk-manifest",
                        "The archive is not a valid Android application.",
                        "AndroidManifest.xml missing",
                        "Rebuild the artifact with a valid manifest.",
                    )
                )
                return report
            raw = archive.read("AndroidManifest.xml")
    except (zipfile.BadZipFile, OSError) as exc:
        report.findings.append(
            _finding(
                "APK is not a readable ZIP container",
                Severity.HIGH,
                "mobile-apk-corrupt",
                "The artifact could not be opened.",
                type(exc).__name__,
                "Verify the build output before shipping.",
            )
        )
        return report

    if raw[:1] == b"<":
        manifest = raw.decode("utf-8", "replace")
        facts = analyze_apk_manifest(manifest)
        report.package = facts["package"]
        report.version_name = facts["version_name"]
        report.version_code = facts["version_code"]
        report.min_sdk = facts["min_sdk"]
        report.target_sdk = facts["target_sdk"]
        report.permissions = facts["permissions"]
        report.components = facts["components"]
        report.debug_build = facts["debuggable"]
        report.allow_backup = facts["allow_backup"]
        report.cleartext_traffic = facts["cleartext"]
        if facts["exported_without_permission"]:
            report.findings.append(
                _finding(
                    "Exported app component without permission",
                    Severity.HIGH,
                    "mobile-apk-exported",
                    "Another app can launch or bind an exported component.",
                    "android:exported=\"true\" without android:permission",
                    "Set android:exported=\"false\" or guard it with a signature permission.",
                    url,
                )
            )
        if report.target_sdk >= 28 and not facts["network_security_config"] and report.cleartext_traffic:
            report.findings.append(
                _finding(
                    "Cleartext traffic allowed without network security config",
                    Severity.HIGH,
                    "mobile-apk-cleartext",
                    "HTTP traffic is permitted for a modern target SDK.",
                    f"targetSdk={report.target_sdk} usesCleartextTraffic=true",
                    "Add a networkSecurityConfig that blocks cleartext traffic.",
                    url,
                )
            )
    else:
        report.manifest_binary = True
        report.findings.append(
            _finding(
                "Binary manifest limits static checks",
                Severity.INFO,
                "mobile-apk-binary-manifest",
                "A compiled AndroidManifest.xml was found; only container-level checks ran.",
                "binary AXML manifest",
                "Use apktool or aapt2 to decode the manifest for deeper checks.",
                url,
            )
        )

    if report.debug_build:
        report.findings.append(
            _finding(
                "Debuggable release build",
                Severity.CRITICAL,
                "mobile-apk-debuggable",
                "android:debuggable is enabled, allowing runtime inspection.",
                "android:debuggable=\"true\"",
                "Ship a release build with debuggable disabled.",
                url,
            )
        )
    if report.allow_backup:
        report.findings.append(
            _finding(
                "Application backup enabled",
                Severity.MEDIUM,
                "mobile-apk-backup",
                "adb backup can extract application data on older devices.",
                "android:allowBackup=\"true\"",
                "Disable allowBackup or scope it with backup rules.",
                url,
            )
        )
    if not report.signed:
        report.findings.append(
            _finding(
                "APK is not signed",
                Severity.CRITICAL,
                "mobile-apk-signature",
                "No v1 signature block was found in META-INF.",
                "META-INF/*.RSA|DSA|EC missing",
                "Sign the release with a protected keystore and verify with apksigner.",
                url,
            )
        )
    if not report.package:
        report.findings.append(
            _finding(
                "APK package name missing",
                Severity.MEDIUM,
                "mobile-apk-package",
                "The manifest does not declare an application package.",
                "package attribute absent",
                "Declare the applicationId in the Gradle manifest.",
                url,
            )
        )
    if report.target_sdk and report.target_sdk < 33:
        report.findings.append(
            _finding(
                "Low target SDK",
                Severity.MEDIUM,
                "mobile-apk-target-sdk",
                "The app targets an Android version below current store requirements.",
                f"targetSdk={report.target_sdk}",
                "Raise targetSdkVersion to the level required by Google Play.",
                url,
            )
        )
    for permission in report.permissions:
        severity = DANGEROUS_PERMISSIONS.get(permission)
        if severity is not None:
            report.findings.append(
                _finding(
                    "Dangerous permission requested",
                    severity,
                    "mobile-apk-permission",
                    f"The manifest requests {permission}.",
                    permission,
                    "Remove the permission or document the user-facing justification.",
                    url,
                )
            )
    if report.dex_count == 0:
        report.findings.append(
            _finding(
                "APK contains no DEX bytecode",
                Severity.MEDIUM,
                "mobile-apk-dex",
                "The container has no classes.dex, so it cannot run on Android.",
                "*.dex count = 0",
                "Verify the packaging step.",
                url,
            )
        )
    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )
    return report


# ---------------------------------------------------------------------------
# PWA
# ---------------------------------------------------------------------------


def manifest_icon_sizes(manifest: Mapping[str, Any]) -> set[str]:
    sizes: set[str] = set()
    for icon in manifest.get("icons") or ():
        if isinstance(icon, Mapping):
            for size in str(icon.get("sizes", "")).split():
                sizes.add(size.strip().lower())
    return sizes


@dataclass
class PwaReport:
    url: str = ""
    name: str = ""
    short_name: str = ""
    display: str = ""
    service_worker: bool = False
    installable: bool = False
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": redact_url(self.url),
            "name": self.name,
            "short_name": self.short_name,
            "display": self.display,
            "service_worker": self.service_worker,
            "installable": self.installable,
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def audit_pwa(
    html: str,
    manifest: Mapping[str, Any] | None,
    service_worker: str = "",
    *,
    url: str = "",
    is_https: bool = True,
) -> PwaReport:
    """Audit PWA installability and offline behaviour from captured sources."""
    report = PwaReport(url=url)
    page = html or ""
    data = manifest if isinstance(manifest, Mapping) else {}
    worker = service_worker or ""
    script_text = f"{page}\n{worker}"
    if str(url).lower().startswith("http://"):
        is_https = False

    def add(title: str, severity: Severity, category: str, description: str, evidence: str, fix: str) -> None:
        report.findings.append(_finding(title, severity, category, description, evidence, fix, url))

    if not data:
        add(
            "Web app manifest missing",
            Severity.HIGH,
            "pwa-manifest",
            "Without a manifest the app cannot be installed.",
            "manifest could not be parsed",
            "Serve a valid manifest.webmanifest and link it from <head>.",
        )
    else:
        report.name = str(data.get("name", ""))
        report.short_name = str(data.get("short_name", ""))
        report.display = str(data.get("display", ""))
        if not report.name:
            add("Manifest name missing", Severity.MEDIUM, "pwa-name", "The manifest has no name.", "name absent", "Add the application name.")
        if not report.short_name:
            add("Manifest short_name missing", Severity.LOW, "pwa-short-name", "The launcher label will be empty.", "short_name absent", "Add a short_name of 12 characters or fewer.")
        elif len(report.short_name) > 12:
            add("Manifest short_name too long", Severity.LOW, "pwa-short-name", "Launchers truncate long labels.", report.short_name, "Shorten short_name to 12 characters or fewer.")
        if not str(data.get("start_url", "")):
            add("Manifest start_url missing", Severity.HIGH, "pwa-start-url", "Installation cannot resolve an entry point.", "start_url absent", "Set start_url to the app entry point.")
        if report.display not in {"standalone", "fullscreen", "minimal-ui"}:
            add("Manifest display is not standalone", Severity.MEDIUM, "pwa-display", "The app opens inside a browser tab.", f"display={report.display or 'absent'}", "Use display=standalone or fullscreen.")
        icons = manifest_icon_sizes(data)
        for required in ("192x192", "512x512"):
            if required not in icons:
                add(
                    "Manifest icon size missing",
                    Severity.HIGH if required == "512x512" else Severity.MEDIUM,
                    "pwa-icons",
                    f"The manifest has no {required} icon.",
                    f"icons={sorted(icons) or 'none'}",
                    f"Add a {required} PNG icon (maskable for Android).",
                )
        if not data.get("theme_color"):
            add("Manifest theme_color missing", Severity.LOW, "pwa-theme", "The browser chrome is not themed.", "theme_color absent", "Add theme_color.")
        if not data.get("background_color"):
            add("Manifest background_color missing", Severity.LOW, "pwa-splash", "The splash screen may flash white.", "background_color absent", "Add background_color.")

    if "rel=\"manifest\"" not in page and "rel='manifest'" not in page:
        add("Manifest not linked from HTML", Severity.HIGH, "pwa-link", "Browsers cannot discover the manifest.", "rel=manifest absent", "Link the manifest in <head>.")
    if not re.search(r"<meta[^>]+name=[\"']viewport[\"']", page, re.IGNORECASE):
        add("Mobile viewport meta missing", Severity.MEDIUM, "pwa-viewport", "The layout will not scale on mobile.", "viewport meta absent", "Add width=device-width, initial-scale=1.")
    if not re.search(r"<meta[^>]+name=[\"']theme-color[\"']", page, re.IGNORECASE):
        add("HTML theme-color meta missing", Severity.LOW, "pwa-theme", "Older browsers ignore the manifest theme.", "meta theme-color absent", "Add a theme-color meta tag.")

    registered = bool(
        re.search(r"serviceWorker\s*\.\s*register", script_text)
        or re.search(r"navigator\.serviceWorker", script_text)
    )
    report.service_worker = registered
    if not registered:
        add("Service worker not registered", Severity.HIGH, "pwa-service-worker", "Offline mode and installability are unavailable.", "serviceWorker.register absent", "Register a service worker from the app entry point.")

    if worker:
        if not re.search(r"addEventListener\(\s*[\"']install[\"']", worker) and "self.addEventListener('install'" not in worker:
            add("Service worker install handler missing", Severity.MEDIUM, "pwa-sw-lifecycle", "The worker cannot pre-cache assets.", "install listener absent", "Add an install handler that precaches the app shell.")
        if "fetch" not in worker:
            add("Service worker has no fetch strategy", Severity.MEDIUM, "pwa-offline", "Requests are not served from cache offline.", "fetch listener absent", "Add a fetch handler with a stale-while-revalidate or cache-first strategy.")
        elif not re.search(r"(caches\.match|cache\.match|cache\.add|precache)", worker):
            add("Service worker fetch handler does not use the cache", Severity.MEDIUM, "pwa-offline", "The worker intercepts requests but never serves cached responses.", "caches.match absent", "Serve cached responses and fall back to the network.")
        if not re.search(r"offline\.html|offlineFallback|fallback", worker):
            add("No offline fallback", Severity.LOW, "pwa-offline", "Navigation failures have no fallback page.", "offline fallback absent", "Cache an offline.html and serve it for failed navigations.")

    if not is_https:
        add("PWA served over HTTP", Severity.HIGH, "pwa-https", "Service workers require a secure context.", "scheme is not https", "Serve the app over HTTPS (localhost is exempt for development).")
    if re.search(r"http://(?!localhost|127\.0\.0\.1)", page, re.IGNORECASE) and is_https:
        add("Mixed content on PWA", Severity.HIGH, "pwa-mixed-content", "Insecure subresources break the secure context.", "http:// reference found", "Load every subresource over HTTPS.")

    report.installable = (
        bool(report.name)
        and bool(report.short_name)
        and report.display in {"standalone", "fullscreen", "minimal-ui"}
        and {"192x192", "512x512"} <= manifest_icon_sizes(data)
        and registered
        and is_https
        and not any(finding.severity == Severity.CRITICAL for finding in report.findings)
    )
    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )
    return report


def audit_pwa_dir(path: str | Path) -> PwaReport:
    """Audit a built PWA folder containing index.html and a manifest."""
    root = Path(path)
    if not root.is_dir():
        return PwaReport(
            url=str(root),
            findings=[
                _finding(
                    "PWA build directory not found",
                    Severity.HIGH,
                    "pwa-path",
                    "The build directory does not exist.",
                    str(root),
                    "Pass the folder produced by the build.",
                )
            ],
        )
    html = ""
    for candidate in ("index.html", "public/index.html", "dist/index.html"):
        if (root / candidate).is_file():
            html = (root / candidate).read_text(encoding="utf-8", errors="replace")
            break
    manifest: dict[str, Any] = {}
    for candidate in ("manifest.webmanifest", "manifest.json", "public/manifest.json", "dist/manifest.webmanifest"):
        if (root / candidate).is_file():
            import json

            try:
                manifest = json.loads((root / candidate).read_text(encoding="utf-8"))
            except ValueError:
                manifest = {}
            break
    worker = ""
    for candidate in ("sw.js", "service-worker.js", "public/sw.js", "dist/sw.js"):
        if (root / candidate).is_file():
            worker = (root / candidate).read_text(encoding="utf-8", errors="replace")
            break
    return audit_pwa(html, manifest, worker, url=str(root), is_https=True)


def fetch_pwa(url: str, *, timeout: float = 10.0) -> PwaReport:
    """Fetch HTML, manifest, and service worker from a live URL."""
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout) as client:
            page = client.get(url)
            html = page.text
            manifest: dict[str, Any] = {}
            link = re.search(
                r"<link[^>]+rel=[\"']manifest[\"'][^>]*href=[\"']([^\"']+)[\"']", html, re.IGNORECASE
            ) or re.search(
                r"<link[^>]+href=[\"']([^\"']+)[\"'][^>]*rel=[\"']manifest[\"']", html, re.IGNORECASE
            )
            if link:
                import json

                manifest_url = str(httpx.URL(url).join(link.group(1)))
                try:
                    manifest = client.get(manifest_url).json()
                except ValueError:
                    manifest = {}
            worker = ""
            register = re.search(r"serviceWorker\s*\.\s*register\(\s*[\"']([^\"']+)", html)
            if register:
                worker_url = str(httpx.URL(url).join(register.group(1)))
                try:
                    worker = client.get(worker_url).text
                except httpx.HTTPError:
                    worker = ""
            return audit_pwa(html, manifest, worker, url=url, is_https=url.lower().startswith("https://"))
    except httpx.HTTPError as exc:
        return PwaReport(
            url=url,
            findings=[
                _finding(
                    "PWA unreachable",
                    Severity.MEDIUM,
                    "pwa-transport",
                    "The target could not be fetched.",
                    type(exc).__name__,
                    "Confirm the URL is reachable before the audit.",
                    url,
                )
            ],
        )
