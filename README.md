# Roger Headers 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**HTTP security header analyzer for bug bounty hunting.**

Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.) and suspicious server information leaks that could aid attackers.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

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

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger Headers helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [Ashlee (Jessica Rabbit)](https://github.com/jrabbit00)