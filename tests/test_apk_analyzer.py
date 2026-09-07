#!/usr/bin/env python3
"""Deterministic offline tests for MO1 — Android APK Analyzer."""

import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import apk_analyzer as mo1


class TestAXMLRoundTrip(unittest.TestCase):
    def test_string_pool_utf16_roundtrip(self):
        strings = ["com.example.lab.wifi", "android.permission.CAMERA",
                   "android:debuggable", "true"]
        manifest = mo1.build_binary_manifest(strings)
        decoded = mo1.APKAnalyzer._decode_binary_xml_strings(mo1.APKAnalyzer, manifest)
        self.assertEqual(decoded, strings)

    def test_string_pool_utf8(self):
        # Force UTF-8 flag in a hand-built pool (builder is UTF-16 only, so
        # generate a UTF-16 pool then flip the flag for decode-path coverage).
        strings = ["alpha", "beta"]
        manifest = bytearray(mo1.build_binary_manifest(strings))
        pool_off = 8
        struct_flag_off = pool_off + 16
        self.assertEqual(mo1.struct.unpack_from("<I", manifest, struct_flag_off)[0], 0)
        mo1.struct.pack_into("<I", manifest, struct_flag_off, 0x100)
        # UTF-8 decoding of UTF-16 data is lossy but must not raise
        decoded = mo1.APKAnalyzer._decode_binary_xml_strings(mo1.APKAnalyzer, bytes(manifest))
        self.assertIsInstance(decoded, list)

    def test_invalid_magic_returns_none(self):
        self.assertIsNone(
            mo1.APKAnalyzer._decode_binary_xml_strings(mo1.APKAnalyzer, b"\x00\x00" + b"\x00" * 64))

    def test_truncated_pool_returns_none(self):
        self.assertIsNone(mo1.APKAnalyzer._decode_binary_xml_strings(mo1.APKAnalyzer, b"\x03\x00\x08\x00" + b"\x01\x00"))


class TestFixtureAPK(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "..", "fixtures", "sample_vuln.apk")
        if not os.path.exists(cls.fixture):
            mo1.create_fixture_apk(cls.fixture)
        cls.analyzer = mo1.APKAnalyzer(cls.fixture)

    def test_valid_zip_structure(self):
        with zipfile.ZipFile(self.fixture) as zf:
            names = zf.namelist()
        self.assertIn("AndroidManifest.xml", names)
        self.assertIn("classes.dex", names)
        self.assertTrue(all(n.endswith(".dex") or n.startswith("lib/") or n.startswith("res/")
                            or n.startswith("META-INF/") or n == "resources.arsc"
                            or n == "AndroidManifest.xml" for n in names))

    def test_analyze_detects_package(self):
        self.assertTrue(self.analyzer.analyze())
        self.assertEqual(self.analyzer.package, "com.example.labwifi.mobile")
        self.assertTrue(self.analyzer.valid)

    def test_permission_categorization(self):
        self.assertIn("android.permission.CAMERA", self.analyzer.dangerous_permissions)
        self.assertIn("android.permission.SEND_SMS", self.analyzer.dangerous_permissions)
        self.assertIn("android.permission.INSTALL_PACKAGES", self.analyzer.signature_permissions)
        self.assertIn("android.permission.INTERNET", self.analyzer.unknown_permissions)
        self.assertGreaterEqual(len(self.analyzer.permissions), 12)

    def test_signing_flag(self):
        self.assertTrue(self.analyzer.signed)
        self.assertTrue(self.analyzer.v2_signature)

    def test_dex_files_scanned(self):
        self.assertGreaterEqual(len(self.analyzer.dex_blobs), 1)
        self.assertIn("classes.dex", self.analyzer.dex_blobs)

    def test_dangerous_api_grep(self):
        self.assertIn("classes.dex", self.analyzer.dangerous_apis)
        descriptions = [a["description"] for v in self.analyzer.dangerous_apis.values() for a in v]
        joined = " ".join(descriptions)
        self.assertIn("Device ID", joined)
        self.assertIn("Shell command", joined)

    def test_hardcoded_secrets(self):
        types = {s["type"] for s in self.analyzer.hardcoded_secrets}
        self.assertIn("aws_access_key", types)
        self.assertIn("rsa_private_key", types)
        self.assertIn("generic_api_key", types)

    def test_summary_json_serializable(self):
        report = self.analyzer.summary()
        json.dumps(report)  # must not raise
        self.assertEqual(report["package"], "com.example.labwifi.mobile")


class TestCli(unittest.TestCase):
    def test_demo_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = mo1.run_demo(os.path.join(tmp, "reports"))
            self.assertEqual(rc, 0)
            report_path = os.path.join(tmp, "reports", "mo1_demo_report.json")
            self.assertTrue(os.path.exists(report_path))
            with open(report_path) as f:
                data = json.load(f)
            self.assertEqual(data["package"], "com.example.labwifi.mobile")

    def test_missing_file_exits_two(self):
        rc = mo1.main(["/nonexistent/file.apk"])
        self.assertEqual(rc, 2)

    def test_make_fixture_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "generated.apk")
            mo1.create_fixture_apk(target)
            rc = mo1.main([target])
            self.assertEqual(rc, 0)

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            mo1.main(["--help"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()