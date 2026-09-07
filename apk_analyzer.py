#!/usr/bin/env python3
"""MO1 — Android APK Analyzer

Real APK parser built on the standard library:
  * zipfile for APK container structure
  * pure-python binary XML (AXML) decoder for AndroidManifest.xml
  * permission risk categorization
  * component enumeration (activities / services / receivers / providers)
  * signature presence check (META-INF, APK Signature Scheme v2 block)
  * dangerous API grep over DEX payload
  * hardcoded-secret scan

CLI:
    python3 apk_analyzer.py                     # offline demo (creates fixture, exit 0)
    python3 apk_analyzer.py --help
    python3 apk_analyzer.py path/to/app.apk --json

WARNING: Educational use only. Only analyze APKs you own or are authorized to assess.
"""

import argparse
import json
import os
import re
import struct
import sys
import zipfile
from collections import defaultdict

DANGEROUS_API_PATTERNS = [
    (r"getDeviceId|getImei|getMeid", "Device ID harvesting"),
    (r"getSubscriberId|getSimSerialNumber", "SIM / IMSI harvesting"),
    (r"SmsManager|sendTextMessage|sendMultipartTextMessage", "SMS sending / exfiltration"),
    (r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder", "Shell command execution"),
    (r"accessibility|performGlobalAction|TYPE_GESTURE", "Accessibility abuse"),
    (r"DexClassLoader|PathClassLoader", "Dynamic code loading"),
    (r"PackageInstaller|ACTION_INSTALL_PACKAGE|REQUEST_INSTALL_PACKAGES", "Sideloading"),
    (r"loadUrl\(.*javascript:|addJavascriptInterface", "JavaScript bridge abuse"),
    (r"Cipher\.getInstance|AES|DESede", "Embedded cryptography"),
    (r"Base64\.decode|Base64\.N0_WRAP", "Obfuscated payload encoding"),
    (r"su\s+-c|/system/bin/su", "Root escalation"),
]

KNOWN_SECRET_PATTERNS = [
    ("google_api_key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("google_oauth", re.compile(rb"ya29\.[0-9A-Za-z_\-]+")),
    ("github_token", re.compile(rb"ghp_[0-9A-Za-z]{36}")),
    ("rsa_private_key", re.compile(rb"-----BEGIN RSA PRIVATE KEY-----")),
    ("generic_password", re.compile(rb"(?i)password\s*[=:]\s*['\"]?[^'\"\s,;}]{4,}")),
    ("generic_api_key", re.compile(rb"(?i)api[_\-]?key\s*[=:]\s*['\"]?[0-9A-Za-z_\-]{12,}")),
    ("generic_secret", re.compile(rb"(?i)secret\s*[=:]\s*['\"]?[^'\"\s,;}]{8,}")),
]


def build_axml_string_pool(strings):
    """Encode a list of unicode strings as an Android binary-XML string pool.

    Uses the classic UTF-16 format (no FLAG_UTF8): each string is written as
      u16 char_count, utf-16-le bytes, u16 terminator (0x0000).
    Layout: [28-byte chunk header][offset table][utf-16 string data].
    """
    header = bytearray(struct.pack("<HHIIIIII", 0x0001, 0x001C, 0, 0, 0, 0, 0, 0))
    string_blob = bytearray()
    offsets = []
    for s in strings:
        offsets.append(len(string_blob))
        u = s.encode("utf-16-le")
        string_blob += struct.pack("<H", len(s))
        string_blob += u
        string_blob += b"\x00\x00"
    table = b"".join(struct.pack("<I", off) for off in offsets)
    string_count = len(strings)
    header_size = 28
    strings_start = header_size + string_count * 4
    chunk_size = strings_start + len(string_blob)
    struct.pack_into("<I", header, 4, chunk_size)
    struct.pack_into("<I", header, 8, string_count)
    struct.pack_into("<I", header, 12, 0)  # styleCount
    struct.pack_into("<I", header, 16, 0)  # flags (UTF-16)
    struct.pack_into("<I", header, 20, strings_start)  # offset to string data
    struct.pack_into("<I", header, 24, 0)  # stylesStart
    return bytes(header) + table + bytes(string_blob)


def build_binary_manifest(strings):
    """Wrap a string pool into a full Android binary XML document (AXML)."""
    pool = build_axml_string_pool(strings)
    xml_header_size = 8
    total = xml_header_size + len(pool)
    xml_header = struct.pack("<HHI", 0x0003, xml_header_size, total)
    return xml_header + pool


class APKAnalyzer:
    """Main APK analysis engine."""

    PERMISSION_CATEGORIES = {
        "dangerous": [
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECEIVE_WAP_PUSH",
            "android.permission.RECEIVE_MMS",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.BODY_SENSORS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        ],
        "signature": [
            "android.permission.INSTALL_PACKAGES",
            "android.permission.DELETE_PACKAGES",
            "android.permission.REBOOT",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
        ],
    }

    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        self.files = []
        self.permissions = []
        self.manifest_axml = None
        self.package = ""
        self.label = ""
        self.version_name = ""
        self.debuggable = False
        self.allow_backup = None
        self.activities = []
        self.services = []
        self.receivers = []
        self.providers = []
        self.intent_filters = defaultdict(list)
        self.meta_data = []
        self.sdk_info = {}
        self.dangerous_permissions = []
        self.signature_permissions = []
        self.unknown_permissions = []
        self.dex_blobs = {}
        self.native_libs = []
        self.resource_files = []
        self.signed = False
        self.v2_signature = False
        self.dangerous_apis = {}
        self.hardcoded_secrets = []
        self.valid = False

    def validate(self):
        """Check that the path is a readable ZIP/APK."""
        try:
            with zipfile.ZipFile(self.apk_path) as zf:
                return zf.testzip() is None
        except (zipfile.BadZipFile, OSError):
            return False

    def analyze(self):
        if not self.validate():
            return False
        self.valid = True
        with zipfile.ZipFile(self.apk_path) as zf:
            self.files = zf.namelist()
            if "AndroidManifest.xml" in self.files:
                self.manifest_axml = zf.read("AndroidManifest.xml")
                self._decode_and_parse_manifest()
            for name in self.files:
                if name.endswith(".dex") and name not in ("", "classes" + name):
                    self.dex_blobs[name] = zf.read(name)
        self._list_native_libs()
        self._list_resource_files()
        self._check_signing()
        self._scan_dangerous_apis()
        self._scan_hardcoded_secrets()
        return True

    # ------------------------------------------------------------------ AXML
    def _decode_and_parse_manifest(self):
        raw = self.manifest_axml or b""
        strings = self._decode_binary_xml_strings(raw)
        if strings is None:
            self.package = "<undecodable-axml>"
            return
        self._apply_string_manifest(strings)

    def _decode_binary_xml_strings(self, data):
        """Decode string pool of a binary XML document.

        Layout: RES_XML_TYPE header (8 bytes) then RES_STRING_POOL_TYPE chunk.
        """
        if len(data) < 8:
            return None
        if struct.unpack_from("<H", data, 0)[0] != 0x0003:
            return None
        # Binary XML: [u16 type][u16 headerSize][u32 size]; the string pool
        # chunk immediately follows this 8-byte header.
        pool_off = struct.unpack_from("<H", data, 2)[0]
        if pool_off == 0:
            pool_off = 8
        if pool_off + 28 > len(data):
            return None
        if struct.unpack_from("<H", data, pool_off)[0] != 0x0001:
            return None

        string_count = struct.unpack_from("<I", data, pool_off + 8)[0]
        flags = struct.unpack_from("<I", data, pool_off + 16)[0]
        strings_start = struct.unpack_from("<I", data, pool_off + 20)[0]
        is_utf8 = bool(flags & (1 << 8))

        if string_count > 4096:
            string_count = 4096
        try:
            offsets = []
            for i in range(string_count):
                off = struct.unpack_from("<I", data, pool_off + 28 + i * 4)[0]
                offsets.append(off)
            strings = []
            for off in offsets:
                pos = pool_off + strings_start + off
                if is_utf8:
                    strings.append(self._read_utf8_string(data, pos))
                else:
                    strings.append(self._read_utf16_string(data, pos))
            return strings
        except (struct.error, IndexError):
            return None

    @staticmethod
    def _read_utf8_string(data, pos):
        def read_uz():
            b0 = data[pos]
            if b0 & 0x80:
                b1 = data[pos + 1]
                v = ((b0 & 0x7F) << 8) | b1
                return v, 2
            return b0, 1

        char_count, n = read_uz()
        byte_count, nb = read_uz()
        start = pos + n + nb
        raw = data[start:start + byte_count]
        return raw.decode("utf-8", errors="replace")

    @staticmethod
    def _read_utf16_string(data, pos):
        char_count = struct.unpack_from("<H", data, pos)[0]
        n = 2
        if char_count & 0x8000:
            high = struct.unpack_from("<H", data, pos + 2)[0]
            char_count = ((char_count & 0x7FFF) << 16) | high
            n = 4
        start = pos + n
        raw = data[start:start + char_count * 2]
        return raw.decode("utf-16-le", errors="replace")

    def _apply_string_manifest(self, strings):
        self.permissions = [s for s in strings if s.startswith("android.permission.")
                            and s.count(".") >= 2]
        self.package = ""
        for s in strings:
            if s.startswith("android."):
                continue
            if "." in s and s.count(".") >= 1 and len(s) < 120 and re.fullmatch(r"[A-Za-z0-9_.]+", s):
                if any(kw in s for kw in (".MainActivity", ".app", ".ui", ".activity", "$")):
                    continue
                if self.package == "":
                    self.package = s
            if s == "android:debuggable":
                self.debuggable = True
            if s == "true":
                self.allow_backup = True if not self.allow_backup else self.allow_backup
        for perm in self.permissions:
            if perm in self.PERMISSION_CATEGORIES["dangerous"]:
                self.dangerous_permissions.append(perm)
            elif perm in self.PERMISSION_CATEGORIES["signature"]:
                self.signature_permissions.append(perm)
            else:
                self.unknown_permissions.append(perm)

    # ------------------------------------------------------------------ misc
    def _list_native_libs(self):
        self.native_libs = [f for f in self.files if f.startswith("lib/") and f.endswith(".so")]

    def _list_resource_files(self):
        self.resource_files = [f for f in self.files if f.startswith("res/")]

    def _check_signing(self):
        self.signed = "META-INF/MANIFEST.MF" in self.files
        self.v2_signature = any(f.endswith(".RSA") or f.endswith(".DSA") or f.endswith(".EC") for f in self.files
                                if f.startswith("META-INF/"))

    def _scan_dangerous_apis(self):
        for name, blob in self.dex_blobs.items():
            for pattern, desc in DANGEROUS_API_PATTERNS:
                matches = sorted(set(re.findall(pattern, blob.decode("latin-1"), re.IGNORECASE)))[:12]
                if matches:
                    self.dangerous_apis.setdefault(name, []).append(
                        {"pattern": pattern, "description": desc, "count": len(matches)})
            for m in re.finditer(rb"(http|https|ftp)://[0-9A-Za-z._\-/:?&=@+#%]{8,200}", blob):
                self.dangerous_apis.setdefault("url_endpoints", []).append(
                    {"pattern": "endpoint", "description": m.group(0).decode("latin-1", "replace"), "count": 1})

    def _scan_hardcoded_secrets(self):
        haystack = b""
        for name, blob in self.dex_blobs.items():
            haystack += blob
        if self.manifest_axml:
            haystack += self.manifest_axml
        for name, pattern in KNOWN_SECRET_PATTERNS:
            for m in pattern.finditer(haystack):
                snippet = m.group(0)[:80]
                self.hardcoded_secrets.append({
                    "type": name,
                    "match": snippet.decode("latin-1", "replace"),
                    "offset": m.start(),
                })
        # dedupe
        seen = set()
        uniq = []
        for s in self.hardcoded_secrets:
            key = (s["type"], s["match"])
            if key not in seen:
                seen.add(key)
                uniq.append(s)
        self.hardcoded_secrets = uniq

    def summary(self):
        return {
            "apk_name": self.apk_name,
            "package": self.package,
            "label": self.label,
            "version_name": self.version_name,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "valid_apk": self.valid,
            "signed": self.signed,
            "v2_signature": self.v2_signature,
            "file_count": len(self.files),
            "dex_count": len(self.dex_blobs),
            "permissions": {
                "total": len(self.permissions),
                "dangerous": self.dangerous_permissions,
                "signature": self.signature_permissions,
                "unknown": self.unknown_permissions,
            },
            "components": {
                "activities": self.activities,
                "services": self.services,
                "receivers": self.receivers,
                "providers": self.providers,
            },
            "sdk_info": self.sdk_info,
            "dangerous_apis": {k: v for k, v in self.dangerous_apis.items()},
            "hardcoded_secrets": self.hardcoded_secrets,
        }


def create_fixture_apk(path):
    """Build a real, crafted APK fixture with a binary-XML manifest."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    manifest_strings = [
        "http://schemas.android.com/apk/res/android",
        "android",
        "com.example.labwifi.mobile",
        "android:name",
        "android:versionCode",
        "android:versionName",
        "android:debuggable",
        "android:allowBackup",
        "android:exported",
        ".MainActivity",
        ".DataSyncService",
        ".SmsRelayReceiver",
        ".ExternalProvider",
        "android.intent.action.MAIN",
        "android.intent.category.LAUNCHER",
        "android.provider.Telephony.SMS_RECEIVED",
        "android.permission.INTERNET",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_PHONE_STATE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.INSTALL_PACKAGES",
        "true",
        "false",
    ]
    manifest = build_binary_manifest(manifest_strings)

    # classes.dex-like payload with obviously injectable markers
    dex_payload = bytearray()
    dex_payload += b"dex\n035\x00"
    dex_payload += b"\x00" * 32
    for s in [
        b"android/os/Build;",
        b"getDeviceId",
        b"getSubscriberId",
        b"SmsManager.getInstance().sendTextMessage",
        b"Runtime.getRuntime().exec(\"su -c sh\")",
        b"DexClassLoader(cx)/sdcard/evil.dex",
        b"http://192.0.2.10/c2/beacon",
        b"https://lab-c2.example.com/exfil?data=",
        b"AWS_KEY=AWSREDACTED_EXAMPLE",
        b"google_api_key=AIzaSyBM0jexample5Y9p6example4Gk",
        b"api_key=\"lab_t0k3n_7h3f7\"",
        b"password=hunter2_lab",
        b"-----BEGIN RSA PRIVATE KEY-----",
    ]:
        dex_payload += b"\x00" + s + b"\x00"
    dex_payload += b"\x00" * 512

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", bytes(manifest))
        zf.writestr("classes.dex", bytes(dex_payload))
        zf.writestr("classes2.dex", b"\x00" * 128)
        zf.writestr("resources.arsc", b"\x00" * 64)
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 64)
        zf.writestr("lib/armeabi-v7a/libnative.so", b"\x7fELF" + b"\x00" * 64)
        zf.writestr("res/layout/activity_main.xml", b"\x00" * 64)
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", b"\x00" * 128)
    return path


def run_demo(report_dir="reports"):
    """Offline demo: generate fixture, analyze, write JSON. Returns exit code."""
    os.makedirs(report_dir, exist_ok=True)
    fixture_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
    os.makedirs(fixture_dir, exist_ok=True)
    fixture = os.path.join(fixture_dir, "sample_vuln.apk")
    if not os.path.exists(fixture):
        create_fixture_apk(fixture)
    print(f"[*] Demo fixture: {fixture}")
    analyzer = APKAnalyzer(fixture)
    if not analyzer.analyze():
        print("[!] Demo failed: fixture not analyzable")
        return 1
    report = analyzer.summary()
    out = os.path.join(report_dir, "mo1_demo_report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] JSON report: {out}")
    print(f"[*] Package: {analyzer.package}")
    print(f"[*] Permissions: {len(analyzer.permissions)} total, "
          f"{len(analyzer.dangerous_permissions)} dangerous")
    print(f"[*] Dangerous API sets: {len(analyzer.dangerous_apis)}")
    print(f"[*] Hardcoded secrets: {len(analyzer.hardcoded_secrets)}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="apk_analyzer",
        description="MO1 — Android APK Analyzer (real AXML + DEX scanning).")
    parser.add_argument("apk", nargs="?", help="path to APK to analyze (omit for offline demo)")
    parser.add_argument("--json", action="store_true", help="write JSON report to reports/")
    parser.add_argument("--report-dir", default="reports", help="directory for reports/ (default: reports)")
    parser.add_argument("--make-fixture", action="store_true",
                        help="build the crafted fixture APK and exit")
    args = parser.parse_args(argv)

    if args.make_fixture:
        fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "fixtures", "sample_vuln.apk")
        create_fixture_apk(fixture)
        print(f"[*] Fixture written: {fixture}")
        return 0

    if not args.apk:
        return run_demo(args.report_dir)

    if not os.path.exists(args.apk):
        print(f"[!] File not found: {args.apk}")
        return 2

    analyzer = APKAnalyzer(args.apk)
    if not analyzer.analyze():
        print("[!] Not a valid APK/ZIP")
        return 2
    report = analyzer.summary()
    print(f"[*] Package: {report['package']}  signed={report['signed']}  "
          f"dangerous perms={len(report['permissions']['dangerous'])}")
    if args.json:
        os.makedirs(args.report_dir, exist_ok=True)
        out = os.path.join(args.report_dir, os.path.basename(args.apk) + ".json")
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] JSON report: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())