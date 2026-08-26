#!/usr/bin/env python3
"""MO1 — Android APK Analyzer

Parses APK structure, analyzes permissions, extracts manifest,
lists components, and analyzes intent filters.
Uses only standard library modules.
"""

import zipfile
import xml.etree.ElementTree as ET
import struct
import os
import json
import sys
from collections import defaultdict


class APKAnalyzer:
    """Main APK analysis class."""

    # Known permission categories
    PERMISSION_CATEGORIES = {
        "dangerous": [
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_AUDIO",
        ],
        "signature": [
            "android.permission.INSTALL_PACKAGES",
            "android.permission.DELETE_PACKAGES",
            "android.permission.REBOOT",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ],
    }

    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        self.files = []
        self.permissions = []
        self.manifest = None
        self.activities = []
        self.services = []
        self.receivers = []
        self.providers = []
        self.intent_filters = defaultdict(list)
        self.meta_data = []
        self.sdk_info = {}
        self.app_info = {}
        self.dangerous_permissions = []
        self.signature_permissions = []
        self.unknown_permissions = []

    def analyze(self):
        """Run full APK analysis."""
        print(f"[*] Analyzing: {self.apk_name}")
        print(f"[*] File size: {os.path.getsize(self.apk_path)} bytes")
        print()

        if not self._validate_apk():
            return False

        self._list_files()
        self._extract_manifest()
        self._parse_manifest()
        self._analyze_permissions()
        self._list_native_libs()
        self._list_dex_files()
        self._list_resource_files()
        self._check_signing()
        return True

    def _validate_apk(self):
        """Validate APK is a valid ZIP file."""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                if zf.testzip() is not None:
                    print("[!] Warning: APK may be corrupted")
                return True
        except zipfile.BadZipFile:
            print("[!] Error: Not a valid ZIP/APK file")
            return False

    def _list_files(self):
        """List all files in the APK."""
        with zipfile.ZipFile(self.apk_path, 'r') as zf:
            self.files = zf.namelist()

    def _extract_manifest(self):
        """Extract and parse AndroidManifest.xml."""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                with zf.open('AndroidManifest.xml') as f:
                    raw = f.read()
                    self.manifest = self._decode_manifest(raw)
        except KeyError:
            print("[!] Warning: AndroidManifest.xml not found")
            self.manifest = None

    def _decode_manifest(self, data):
        """Decode binary AndroidManifest.xml into parseable XML string."""
        # Android manifest is often compiled binary XML
        # Try parsing as XML first (plain text manifest)
        try:
            text = data.decode('utf-8')
            if '<?xml' in text or '<manifest' in text:
                return ET.fromstring(text)
        except (UnicodeDecodeError, ET.ParseError):
            pass

        # Try as binary XML - simple parser
        try:
            return self._parse_binary_xml(data)
        except Exception:
            # Return None if we can't decode
            return None

    def _parse_binary_xml(self, data):
        """Parse Android binary XML format."""
        if len(data) < 8:
            return None

        # Check magic number
        magic = struct.unpack_from('<H', data, 0)[0]
        if magic != 0x0003:
            return None

        # This is a simplified parser - in production use axmlparser
        # For demo purposes, try to extract strings
        try:
            # String pool offset
            strings_offset = struct.unpack_from('<I', data, 4)[0]
            # Skip to string pool
            if strings_offset < len(data):
                return self._extract_strings_from_binary(data, strings_offset)
        except (struct.error, IndexError):
            pass

        return None

    def _extract_strings_from_binary(self, data, offset):
        """Extract strings from binary XML string pool."""
        try:
            # String pool chunk
            chunk_type = struct.unpack_from('<H', data, offset)[0]
            if chunk_type != 0x0001:  # RES_STRING_POOL_TYPE
                return None

            header_size = struct.unpack_from('<H', data, offset + 2)[0]
            chunk_size = struct.unpack_from('<I', data, offset + 4)[0]

            string_count = struct.unpack_from('<I', data, offset + 8)[0]
            style_count = struct.unpack_from('<I', data, offset + 12)[0]
            flags = struct.unpack_from('<I', data, offset + 16)[0]
            strings_start = struct.unpack_from('<I', data, offset + 20)[0]
            styles_start = struct.unpack_from('<I', data, offset + 24)[0]

            is_utf8 = (flags & (1 << 8)) != 0

            strings = []
            pos = offset + 28

            for _ in range(min(string_count, 500)):
                if is_utf8:
                    # UTF-8 string
                    char_count = data[pos]
                    pos += 1
                    if char_count & 0x80:
                        char_count = ((char_count & 0x7f) << 8) | data[pos + 1]
                        pos += 2
                    byte_count = data[pos]
                    pos += 1
                    if byte_count & 0x80:
                        byte_count = ((byte_count & 0x7f) << 8) | data[pos + 1]
                        pos += 2
                    string_bytes = data[pos:pos + byte_count]
                    pos += byte_count
                    try:
                        strings.append(string_bytes.decode('utf-8', errors='replace'))
                    except Exception:
                        strings.append('')
                else:
                    # UTF-16 string
                    char_count = struct.unpack_from('<H', data, pos)[0]
                    pos += 2
                    if char_count & 0x8000:
                        char_count = ((char_count & 0x7fff) << 16) | struct.unpack_from('<H', data, pos + 2)[0]
                        pos += 4
                    byte_count = char_count * 2
                    string_bytes = data[pos:pos + byte_count + 2]
                    pos += byte_count + 2
                    try:
                        strings.append(string_bytes.decode('utf-16-le', errors='replace'))
                    except Exception:
                        strings.append('')

            # Build a simple XML-like structure from extracted strings
            manifest_attrs = []
            for s in strings:
                if s.startswith('android.permission.'):
                    manifest_attrs.append(s)
                elif s.startswith('android:name'):
                    pass

            return self._build_manifest_from_strings(strings)

        except (struct.error, IndexError, UnicodeDecodeError):
            return None

    def _build_manifest_from_strings(self, strings):
        """Build manifest data structure from extracted strings."""
        # This is a simplified representation
        # In production, you'd use a proper AXML parser

        class ManifestData:
            def __init__(self, strings):
                self.strings = strings
                self.permissions = [s for s in strings if s.startswith('android.permission.')]
                self.components = []
                self.package = ''
                self.version = ''

                # Try to find package name
                for i, s in enumerate(strings):
                    if '.' in s and not s.startswith('android.') and len(s) < 100:
                        parts = s.split('.')
                        if all(p.isalnum() or p == '_' for p in parts):
                            self.package = s
                            break

            def findall(self, tag):
                return []

            def find(self, tag):
                return None

            def get(self, attr, default=None):
                return default

            def attrib(self):
                return {}

        return ManifestData(strings)

    def _parse_manifest(self):
        """Parse manifest XML and extract components."""
        if self.manifest is None:
            print("[!] No manifest to parse")
            return

        # Handle both real XML and our simplified ManifestData
        if hasattr(self.manifest, 'permissions'):
            self.permissions = self.manifest.permissions
            return

        # Real XML parsing
        try:
            root = self.manifest
            if root is None:
                return

            # Package info
            self.app_info['package'] = root.get('package', 'unknown')

            # SDK info
            sdk = root.find('.//uses-sdk')
            if sdk is not None:
                self.sdk_info['min_sdk'] = sdk.get('android:minSdkVersion', 'unknown')
                self.sdk_info['target_sdk'] = sdk.get('android:targetSdkVersion', 'unknown')
                self.sdk_info['max_sdk'] = sdk.get('android:maxSdkVersion', 'unknown')

            # Application info
            app = root.find('.//application')
            if app is not None:
                self.app_info['label'] = app.get('android:label', 'unknown')
                self.app_info['icon'] = app.get('android:icon', 'unknown')
                self.app_info['debuggable'] = app.get('android:debuggable', 'false')
                self.app_info['allow_backup'] = app.get('android:allowBackup', 'unknown')

            # Permissions
            for perm in root.findall('.//uses-permission'):
                name = perm.get('android:name', '')
                if name:
                    self.permissions.append(name)

            # Activities
            for activity in root.findall('.//activity'):
                name = activity.get('android:name', '')
                exported = activity.get('android:exported', 'false')
                self.activities.append({'name': name, 'exported': exported})

                # Intent filters for activity
                for intent_filter in activity.findall('intent-filter'):
                    self._parse_intent_filter(intent_filter, name, 'activity')

            # Services
            for service in root.findall('.//service'):
                name = service.get('android:name', '')
                exported = service.get('android:exported', 'false')
                self.services.append({'name': name, 'exported': exported})

            # Receivers
            for receiver in root.findall('.//receiver'):
                name = receiver.get('android:name', '')
                exported = receiver.get('android:exported', 'false')
                self.receivers.append({'name': name, 'exported': exported})

                for intent_filter in receiver.findall('intent-filter'):
                    self._parse_intent_filter(intent_filter, name, 'receiver')

            # Content Providers
            for provider in root.findall('.//provider'):
                name = provider.get('android:name', '')
                exported = provider.get('android:exported', 'false')
                authority = provider.get('android:authorities', 'unknown')
                self.providers.append({
                    'name': name,
                    'exported': exported,
                    'authority': authority
                })

            # Meta-data
            for meta in root.findall('.//meta-data'):
                name = meta.get('android:name', '')
                value = meta.get('android:value', '')
                self.meta_data.append({'name': name, 'value': value})

        except ET.ParseError as e:
            print(f"[!] Manifest parse error: {e}")

    def _parse_intent_filter(self, intent_filter, component_name, component_type):
        """Parse an intent-filter element."""
        actions = []
        categories = []
        data_schemes = []
        data_hosts = []
        data_paths = []
        data_types = []

        for action in intent_filter.findall('action'):
            name = action.get('android:name', '')
            if name:
                actions.append(name)

        for category in intent_filter.findall('category'):
            name = category.get('android:name', '')
            if name:
                categories.append(name)

        for data in intent_filter.findall('data'):
            scheme = data.get('android:scheme', '')
            host = data.get('android:host', '')
            path = data.get('android:path', '') or data.get('android:pathPattern', '')
            mime_type = data.get('android:mimeType', '')

            if scheme:
                data_schemes.append(scheme)
            if host:
                data_hosts.append(host)
            if path:
                data_paths.append(path)
            if mime_type:
                data_types.append(mime_type)

        if actions or categories:
            filter_info = {
                'component': component_name,
                'type': component_type,
                'actions': actions,
                'categories': categories,
                'data_schemes': data_schemes,
                'data_hosts': data_hosts,
                'data_paths': data_paths,
                'data_types': data_types,
            }
            self.intent_filters[component_name].append(filter_info)

    def _analyze_permissions(self):
        """Analyze permissions by risk category."""
        for perm in self.permissions:
            if perm in self.PERMISSION_CATEGORIES['dangerous']:
                self.dangerous_permissions.append(perm)
            elif perm in self.PERMISSION_CATEGORIES['signature']:
                self.signature_permissions.append(perm)
            else:
                self.unknown_permissions.append(perm)

    def _list_native_libs(self):
        """List native libraries in the APK."""
        self.native_libs = [f for f in self.files if f.startswith('lib/') and f.endswith('.so')]

    def _list_dex_files(self):
        """List DEX files in the APK."""
        self.dex_files = [f for f in self.files if f.endswith('.dex')]

    def _list_resource_files(self):
        """List resource files."""
        self.resource_files = [f for f in self.files if f.startswith('res/')]

    def _check_signing(self):
        """Check APK signing status."""
        self.signed = 'META-INF/MANIFEST.MF' in self.files

    def print_report(self):
        """Print formatted analysis report."""
        print("=" * 60)
        print(f"  MO1 — Android APK Analyzer Report")
        print("=" * 60)
        print(f"\nAPK: {self.apk_name}")
        print(f"Size: {os.path.getsize(self.apk_path)} bytes")
        print(f"Files: {len(self.files)}")

        # App Info
        print(f"\n{'='*60}")
        print("  APP INFORMATION")
        print(f"{'='*60}")
        for key, value in self.app_info.items():
            print(f"  {key:20}: {value}")

        # SDK Info
        if self.sdk_info:
            print(f"\n{'='*60}")
            print("  SDK INFORMATION")
            print(f"{'='*60}")
            for key, value in self.sdk_info.items():
                print(f"  {key:20}: {value}")

        # Permissions
        print(f"\n{'='*60}")
        print(f"  PERMISSIONS ({len(self.permissions)} total)")
        print(f"{'='*60}")

        if self.dangerous_permissions:
            print(f"\n  [!] DANGEROUS PERMISSIONS ({len(self.dangerous_permissions)}):")
            for perm in sorted(self.dangerous_permissions):
                print(f"      - {perm}")

        if self.signature_permissions:
            print(f"\n  [i] SIGNATURE PERMISSIONS ({len(self.signature_permissions)}):")
            for perm in sorted(self.signature_permissions):
                print(f"      - {perm}")

        if self.unknown_permissions:
            print(f"\n  [?] OTHER PERMISSIONS ({len(self.unknown_permissions)}):")
            for perm in sorted(self.unknown_permissions):
                print(f"      - {perm}")

        # Components
        print(f"\n{'='*60}")
        print("  COMPONENTS")
        print(f"{'='*60}")

        if self.activities:
            print(f"\n  Activities ({len(self.activities)}):")
            for act in self.activities:
                exported_mark = " [EXPORTED]" if act['exported'] == 'true' else ""
                print(f"    - {act['name']}{exported_mark}")

        if self.services:
            print(f"\n  Services ({len(self.services)}):")
            for svc in self.services:
                exported_mark = " [EXPORTED]" if svc['exported'] == 'true' else ""
                print(f"    - {svc['name']}{exported_mark}")

        if self.receivers:
            print(f"\n  Receivers ({len(self.receivers)}):")
            for rec in self.receivers:
                exported_mark = " [EXPORTED]" if rec['exported'] == 'true' else ""
                print(f"    - {rec['name']}{exported_mark}")

        if self.providers:
            print(f"\n  Content Providers ({len(self.providers)}):")
            for prov in self.providers:
                exported_mark = " [EXPORTED]" if prov['exported'] == 'true' else ""
                print(f"    - {prov['name']}{exported_mark}")
                print(f"      Authority: {prov['authority']}")

        # Intent Filters
        if self.intent_filters:
            print(f"\n{'='*60}")
            print(f"  INTENT FILTERS ({sum(len(v) for v in self.intent_filters.values())} total)")
            print(f"{'='*60}")

            for component, filters in self.intent_filters.items():
                print(f"\n  Component: {component}")
                for i, f in enumerate(filters, 1):
                    print(f"    Filter {i}:")
                    if f['actions']:
                        print(f"      Actions: {', '.join(f['actions'])}")
                    if f['categories']:
                        print(f"      Categories: {', '.join(f['categories'])}")
                    if f['data_schemes']:
                        print(f"      Schemes: {', '.join(f['data_schemes'])}")
                    if f['data_hosts']:
                        print(f"      Hosts: {', '.join(f['data_hosts'])}")
                    if f['data_paths']:
                        print(f"      Paths: {', '.join(f['data_paths'])}")
                    if f['data_types']:
                        print(f"      MIME: {', '.join(f['data_types'])}")

        # Files
        print(f"\n{'='*60}")
        print("  FILE STRUCTURE")
        print(f"{'='*60}")

        print(f"\n  DEX Files: {len(self.dex_files)}")
        for dex in self.dex_files:
            print(f"    - {dex}")

        if hasattr(self, 'native_libs') and self.native_libs:
            print(f"\n  Native Libraries: {len(self.native_libs)}")
            for lib in self.native_libs:
                print(f"    - {lib}")

        print(f"\n  Resources: {len(self.resource_files)}")

        # Signing
        print(f"\n{'='*60}")
        print("  SIGNING STATUS")
        print(f"{'='*60}")
        print(f"  Signed: {'Yes' if self.signed else 'No (unsigned APK)'}")

        # Security Observations
        print(f"\n{'='*60}")
        print("  SECURITY OBSERVATIONS")
        print(f"{'='*60}")

        if self.app_info.get('debuggable') == 'true':
            print("  [!] App is DEBUGGABLE - should not be in production")

        if self.app_info.get('allow_backup') == 'true':
            print("  [!] Backup allowed - data can be extracted via ADB")

        exported_activities = [a for a in self.activities if a['exported'] == 'true']
        if exported_activities:
            print(f"  [i] {len(exported_activities)} exported activity(ies)")

        if self.dangerous_permissions:
            print(f"  [!] {len(self.dangerous_permissions)} dangerous permission(s) requested")

        if self.intent_filters:
            print(f"  [i] {sum(len(v) for v in self.intent_filters.values())} intent filter(s) defined")

        print(f"\n{'='*60}")
        print("  Analysis Complete")
        print(f"{'='*60}\n")

    def export_json(self, output_path):
        """Export analysis results to JSON."""
        results = {
            'apk_name': self.apk_name,
            'file_size': os.path.getsize(self.apk_path),
            'total_files': len(self.files),
            'app_info': self.app_info,
            'sdk_info': self.sdk_info,
            'permissions': self.permissions,
            'dangerous_permissions': self.dangerous_permissions,
            'activities': self.activities,
            'services': self.services,
            'receivers': self.receivers,
            'providers': self.providers,
            'intent_filters': {k: v for k, v in self.intent_filters.items()},
            'meta_data': self.meta_data,
            'signed': self.signed,
        }

        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results exported to {output_path}")


def create_sample_apk():
    """Create a sample APK-like ZIP file for demonstration."""
    sample_path = '/tmp/sample_test.apk'

    manifest_xml = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.CALL_PHONE" />

    <application
        android:label="TestApp"
        android:icon="@drawable/ic_launcher"
        android:debuggable="true"
        android:allowBackup="true">

        <activity android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity android:name=".SettingsActivity"
            android:exported="false" />

        <service android:name=".TrackingService"
            android:exported="true">
            <intent-filter>
                <action android:name="com.example.testapp.TRACK" />
            </intent-filter>
        </service>

        <receiver android:name=".BootReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <provider android:name=".DataProvider"
            android:exported="true"
            android:authorities="com.example.testapp.provider" />

        <meta-data android:name="API_KEY" android:value="secret123" />
    </application>
</manifest>'''

    with zipfile.ZipFile(sample_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('AndroidManifest.xml', manifest_xml)
        zf.writestr('classes.dex', b'\x00' * 1024)
        zf.writestr('classes2.dex', b'\x00' * 512)
        zf.writestr('resources.arsc', b'\x00' * 256)
        zf.writestr('lib/arm64-v8a/libnative.so', b'\x7fELF' + b'\x00' * 100)
        zf.writestr('lib/armeabi-v7a/libnative.so', b'\x7fELF' + b'\x00' * 100)
        zf.writestr('res/layout/activity_main.xml', b'\x00' * 100)
        zf.writestr('res/drawable/ic_launcher.png', b'\x00' * 50)
        zf.writestr('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\n')
        zf.writestr('META-INF/CERT.SF', b'Signature-Version: 1.0\n')
        zf.writestr('META-INF/CERT.RSA', b'\x00' * 200)

    return sample_path


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python3 apk_analyzer.py <apk_file>")
        print("\nGenerating sample APK for demonstration...")
        apk_path = create_sample_apk()
        print(f"Sample APK created at: {apk_path}")
    else:
        apk_path = sys.argv[1]

    if not os.path.exists(apk_path):
        print(f"[!] File not found: {apk_path}")
        sys.exit(1)

    analyzer = APKAnalyzer(apk_path)
    if analyzer.analyze():
        analyzer.print_report()

        # Export JSON if requested
        if '--json' in sys.argv:
            json_path = apk_path.replace('.apk', '_analysis.json')
            analyzer.export_json(json_path)


if __name__ == '__main__':
    main()
