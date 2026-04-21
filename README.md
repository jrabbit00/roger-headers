# Roger Headers 🐰

HTTP security header analyzer for bug bounty hunting. Checks for missing security headers and suspicious server information leaks.

## Why Security Headers?

Security headers are critical for web application defense:
- **CSP** - Prevents XSS attacks
- **HSTS** - Enforces HTTPS
- **X-Frame-Options** - Prevents clickjacking
- **Referrer-Policy** - Controls privacy leaks

## Features

- Checks 14 security headers
- Severity ratings (HIGH/MEDIUM/LOW)
- Missing header recommendations
- Suspicious header detection (X-Powered-By, Server version)
- Detailed analysis with fix recommendations

## Installation

```bash
git clone https://github.com/jrabbit00/roger-headers.git
cd roger-headers
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 headers.py https://target.com

# Save results
python3 headers.py target.com -o findings.txt
```

## What It Checks

**Missing (High):**
- Content-Security-Policy (HIGH)
- Strict-Transport-Security (HIGH)

**Missing (Medium):**
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy

**Missing (Low):**
- X-XSS-Protection
- Cache-Control
- Clear-Site-Data

**Suspicious (should remove):**
- X-Powered-By
- X-AspNet-Version
- Server version info

## Examples

```bash
python3 headers.py https://example.com
python3 headers.py example.com -q
```

## License

MIT License