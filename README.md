# MO1 — Android APK Analyzer

Real APK parser for static mobile security review. Standard-library only.

## What the engine genuinely does

- **ZIP/APK container parsing** via `zipfile` — validates archive, lists entries,
  checks `.testzip()` integrity.
- **Binary XML (AXML) decode, by hand** — parses the RES_XML_TYPE header and the
  RES_STRING_POOL_TYPE chunk (UTF-16 and UTF-8 string pools, real offset table) to
  recover `AndroidManifest.xml` strings without any third-party library.
- **Permission risk categorization** — dangerous / signature / unknown buckets.
- **Signature presence** — META-INF entries and APK Signature Scheme v2 markers.
- **Dangerous API grep** over DEX payload bytes — device-ID, SIM harvesting, SMS,
  shell exec, accessibility abuse, dynamic class loading, C2-style endpoints.
- **Hardcoded-secret scan** — AWS keys, Google API keys, GitHub tokens, RSA private
  blocks, generic password/api_key/secret assignments on DEX+manifest content.
- **Crafted fixture** — `fixtures/sample_vuln.apk` is a real zipfile with a real
  binary-XML manifest and a `classes.dex` payload studded with in-band markers.

## Quick start

```bash
# Offline demo (builds/uses the crafted fixture, writes reports/, exits 0)
python3 apk_analyzer.py

# Analyze any APK
python3 apk_analyzer.py path/to/app.apk

# JSON report + custom report dir
python3 apk_analyzer.py path/to/app.apk --json --report-dir reports

# Rebuild the bundled fixture
python3 apk_analyzer.py --make-fixture

# Tests
python3 -m unittest discover -s tests
```

## CLI

```
python3 apk_analyzer.py [-h] [--json] [--report-dir REPORT_DIR] [--make-fixture] [apk]
```

- `apk` — path to an APK. Omitted → offline demo (exit 0).
- `--json` — write JSON to `reports/<name>.json` (gitignored).
- `--report-dir` — report output directory (default `reports/`).
- `--make-fixture` — regenerate the crafted fixture APK and exit.

Exit codes: `0` success (incl. demo), `2` usage/input error.

## Live Lab Test Plan

Prerequisites: an Android emulator or device you own, and the target `.apk` you
are authorized to analyze (or this repo's fixture as a stand-in).

1. **Baseline**: `python3 apk_analyzer.py fixtures/sample_vuln.apk --json`
   — confirm package, 12 permissions we planted, 9 dangerous, 5 secrets.
2. **Real target**: obtain a signed, debug, or release APK you have rights to;
   run the same command. Sanity-check that `package`/`signed` match `aapt dump badging`.
3. **Cross-check AXML**: decode the same `AndroidManifest.xml` with `apktool` or
   `aapt2 dump xmltree` and compare the permission list against the tool's output.
4. **Secrets audit**: diff the hardcoded-secret findings against `strings` /
   `grep -a` output for the same DEX to confirm recall and check false positives.
5. **Regression**: re-run `python3 -m unittest discover -s tests` after any change
   to the decoder.

## Metrics

| Metric                                  | Value |
|-----------------------------------------|-------|
| Standard-library only                   | Yes   |
| Third-party deps                        | none  |
| Deterministic offline tests             | 16    |
| Fixture APK (real zipfile + AXML)       | `fixtures/sample_vuln.apk` |
| Offline demo exit                      | 0     |
| Report output                          | `reports/*.json` (gitignored) |
| Input formats                           | APK (zipfile), AXML manifest |

## IMPORTANT: Read before use.

Educational, authorization-required tooling. See `LICENSE` for the full shield —
Authorization, CFAA / computer-crime statutes, Acceptable Use, Prohibited Use,
No Warranty, and Responsible Disclosure. Only analyze APKs you own or are
explicitly authorized to assess.

## License

MIT — full legal shield in `LICENSE`.