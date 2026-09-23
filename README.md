> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# MO1 — Android APK Analyzer

Standalone, standard-library-only APK static analyzer for mobile security review: parses the APK container, decodes binary XML manifests by hand, and greps DEX payloads for risky APIs and hardcoded secrets — fully offline.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/mo1-apk-analyzer.svg)](https://github.com/5h4d0wn1k/mo1-apk-analyzer)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/mo1-apk-analyzer.svg)](https://github.com/5h4d0wn1k/mo1-apk-analyzer)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/mo1-apk-analyzer.svg)](https://github.com/5h4d0wn1k/mo1-apk-analyzer)

## Why

Static mobile analysis should be reproducible and dependency-free. MO1 performs real APK forensics in pure Python — no Android SDK, no apktool, no third-party imports — so you can inspect permissions, components, signatures, risky API usage, and embedded secrets on any machine, including air-gapped review boxes. Analyze only APKs you own or are explicitly authorized to assess.

## Features

- **ZIP/APK container parsing** via `zipfile` — archive validation, entry listing, `.testzip()` integrity
- **Hand-written binary XML (AXML) decoder** — parses `RES_XML_TYPE` and `RES_STRING_POOL_TYPE` chunks (UTF-16/UTF-8 pools, real offset tables) to recover `AndroidManifest.xml`
- **Permission risk categorization** — dangerous / signature / unknown buckets
- **Signature presence check** — `META-INF` entries and APK Signature Scheme v2 markers
- **Dangerous API grep over DEX bytes** — device-ID, SIM/IMSI harvesting, SMS, shell exec, accessibility abuse, dynamic class loading, C2-style endpoints
- **Hardcoded-secret scan** — AWS keys, Google API keys, GitHub tokens, RSA private blocks, generic password/secret assignments
- **Bundled crafted fixture** — `fixtures/sample_vuln.apk` (real zipfile + binary XML manifest + marked DEX payload)

## Quickstart

```bash
# Offline demo (writes reports/, exit 0)
python3 apk_analyzer.py

# Analyze any APK you are authorized to inspect
python3 apk_analyzer.py path/to/app.apk

# JSON report + custom report directory
python3 apk_analyzer.py path/to/app.apk --json --report-dir reports

# Rebuild the bundled fixture
python3 apk_analyzer.py --make-fixture
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Project structure

- `apk_analyzer.py` — parser, AXML decoder, scanners and CLI
- `fixtures/` — `sample_vuln.apk`, a real crafted analysis target
- `tests/` — 16 unit tests over the full pipeline

## Documentation

- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — safe contribution guidelines

## Contributing

New risky-API patterns, secret detectors, and fixture improvements are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); analysis targets must remain fixtures or APKs you own.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, without warranty, for education and authorized mobile security testing only.