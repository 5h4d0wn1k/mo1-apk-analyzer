# MO1 — Android APK Analyzer

Parses Android APK structure, analyzes permissions, extracts manifest, lists components, and analyzes intent filters.

## Overview

This tool performs static analysis of Android APK files to identify:
- APK structure and file composition
- Permission usage and risk categorization
- AndroidManifest.xml parsing
- Component enumeration (activities, services, receivers, providers)
- Intent filter analysis
- Security observations (debuggable, backup, exported components)

## Features

- **APK Structure Parsing**: List all files and analyze ZIP structure
- **Permission Analysis**: Categorize permissions by risk level (dangerous, signature, unknown)
- **Manifest Extraction**: Parse AndroidManifest.xml for app metadata
- **Component Listing**: Enumerate activities, services, receivers, content providers
- **Intent Filter Analysis**: Map intent filters to components
- **Security Observations**: Flag debuggable apps, backup enabled, exported components

## Installation

```bash
# No external dependencies required - uses standard library only
python3 apk_analyzer.py <apk_file>
```

## Usage

```bash
# Analyze an APK file
python3 apk_analyzer.py app.apk

# Generate and analyze sample APK
python3 apk_analyzer.py

# Export results to JSON
python3 apk_analyzer.py app.apk --json
```

## Example Output

```
[*] Analyzing: sample.apk
[*] File size: 12345 bytes

============================================================
  MO1 — Android APK Analyzer Report
============================================================

APK: sample.apk
Size: 12345 bytes
Files: 15

============================================================
  APP INFORMATION
============================================================
  package             : com.example.testapp
  label               : TestApp
  debuggable          : true
  allow_backup        : true

============================================================
  PERMISSIONS (10 total)
============================================================

  [!] DANGEROUS PERMISSIONS (6):
      - android.permission.CAMERA
      - android.permission.READ_CONTACTS
      - android.permission.READ_EXTERNAL_STORAGE
      - android.permission.RECORD_AUDIO
      - android.permission.SEND_SMS
      - android.permission.ACCESS_FINE_LOCATION

============================================================
  COMPONENTS
============================================================

  Activities (2):
    - .MainActivity [EXPORTED]
    - .SettingsActivity

  Services (1):
    - .TrackingService [EXPORTED]

  Receivers (1):
    - .BootReceiver [EXPORTED]

============================================================
  SECURITY OBSERVATIONS
============================================================
  [!] App is DEBUGGABLE - should not be in production
  [!] Backup allowed - data can be extracted via ADB
  [!] 6 dangerous permission(s) requested
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
