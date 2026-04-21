#!/usr/bin/env python3
"""
Roger Headers - HTTP security header analyzer for bug bounty hunting.
"""

import argparse
import requests
import urllib3
import sys
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Security headers to check
SECURITY_HEADERS = {
    # Content Security Policy
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Prevents XSS and data injection attacks",
        "recommendation": "Implement CSP header with appropriate directives"
    },
    # HTTP Strict Transport Security
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Enforces HTTPS connections",
        "recommendation": "Enable HSTS with max-age of at least 31536000"
    },
    # X-Frame-Options
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Prevents clickjacking attacks",
        "recommendation": "Set to DENY or SAMEORIGIN"
    },
    # X-Content-Type-Options
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing",
        "recommendation": "Set to 'nosniff'"
    },
    # X-XSS-Protection
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS filter (deprecated but still useful)",
        "recommendation": "Set to '1; mode=block'"
    },
    # Referrer-Policy
    "Referrer-Policy": {
        "severity": "MEDIUM",
        "description": "Controls referrer information sent with requests",
        "recommendation": "Set to 'strict-origin-when-cross-origin' or 'no-referrer'"
    },
    # Permissions-Policy
    "Permissions-Policy": {
        "severity": "MEDIUM",
        "description": "Controls browser features and APIs",
        "recommendation": "Disable unnecessary features"
    },
    # Cross-Origin Opener Policy
    "Cross-Origin-Opener-Policy": {
        "severity": "MEDIUM",
        "description": "Isolates browsing context",
        "recommendation": "Set to 'same-origin' or 'same-origin-allow-popups'"
    },
    # Cross-Origin Resource Policy
    "Cross-Origin-Resource-Policy": {
        "severity": "MEDIUM",
        "description": "Prevents cross-origin loading of resources",
        "recommendation": "Set to 'same-origin' or 'same-site'"
    },
    # Cross-Origin Embedder Policy
    "Cross-Origin-Embedder-Policy": {
        "severity": "MEDIUM",
        "description": "Controls cross-origin resource loading",
        "recommendation": "Set to 'require-corp' for COEP"
    },
    # Cache-Control
    "Cache-Control": {
        "severity": "LOW",
        "description": "Controls caching behavior",
        "recommendation": "Set to 'no-store, no-cache, must-revalidate' for sensitive pages"
    },
    # Pragma
    "Pragma": {
        "severity": "LOW",
        "description": "Cache control for HTTP/1.0",
        "recommendation": "Set to 'no-cache' for sensitive pages"
    },
    # Clear-Site-Data
    "Clear-Site-Data": {
        "severity": "LOW",
        "description": "Clears cached data",
        "recommendation": "Use on logout endpoints"
    },
}

# Headers that should NOT be present (potential issues)
SUSPICIOUS_HEADERS = {
    "X-Powered-By": {
        "severity": "LOW",
        "description": "Reveals server technology information",
        "recommendation": "Remove X-Powered-By header"
    },
    "X-AspNet-Version": {
        "severity": "LOW",
        "description": "Reveals ASP.NET version",
        "recommendation": "Remove X-AspNet-Version header"
    },
    "Server": {
        "severity": "LOW",
        "description": "Reveals server information",
        "recommendation": "Configure server to hide version info"
    },
}


class RogerHeaders:
    def __init__(self, target, quiet=False, output=None):
        self.target = target
        self.quiet = quiet
        self.output = output
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        
    def parse_url(self, url):
        """Parse URL and add protocol if needed."""
        if not url.startswith('http'):
            url = 'https://' + url
        return url.rstrip('/')
    
    def analyze_headers(self, headers):
        """Analyze response headers for security issues."""
        results = {
            "missing": [],
            "present": [],
            "suspicious": [],
            "info": []
        }
        
        # Check required security headers
        for header, info in SECURITY_HEADERS.items():
            header_lower = header.lower()
            header_value = None
            
            # Search for header (case-insensitive)
            for key, value in headers.items():
                if key.lower() == header_lower:
                    header_value = value
                    break
            
            if header_value:
                results["present"].append({
                    "header": header,
                    "value": header_value,
                    "severity": info["severity"],
                    "description": info["description"]
                })
            else:
                results["missing"].append({
                    "header": header,
                    "severity": info["severity"],
                    "description": info["description"],
                    "recommendation": info["recommendation"]
                })
        
        # Check for suspicious headers
        for header, info in SUSPICIOUS_HEADERS.items():
            header_lower = header.lower()
            header_value = None
            
            for key, value in headers.items():
                if key.lower() == header_lower:
                    header_value = value
                    break
            
            if header_value:
                results["suspicious"].append({
                    "header": header,
                    "value": header_value,
                    "severity": info["severity"],
                    "description": info["description"],
                    "recommendation": info["recommendation"]
                })
        
        return results
    
    def scan(self):
        """Run the header scanner."""
        target = self.parse_url(self.target)
        
        print(f"[*] Analyzing security headers for: {target}")
        print("=" * 60)
        
        try:
            response = self.session.get(target, timeout=15, verify=False)
            status = response.status_code
            
            print(f"[*] Status: {status}")
            print(f"[*] Response headers: {len(response.headers)}")
            print()
            
            # Analyze headers
            results = self.analyze_headers(response.headers)
            
            # Print results
            print("=" * 60)
            
            # Missing headers
            if results["missing"]:
                print("[!] MISSING SECURITY HEADERS:")
                print()
                for item in results["missing"]:
                    print(f"  [{item['severity']}] {item['header']}")
                    print(f"      {item['description']}")
                    print(f"      → {item['recommendation']}")
                    print()
                    self.findings.append(item)
            
            # Present headers
            if results["present"] and not self.quiet:
                print("[+] PRESENT SECURITY HEADERS:")
                print()
                for item in results["present"]:
                    value = item["value"]
                    if len(value) > 60:
                        value = value[:60] + "..."
                    print(f"  [✓] {item['header']}: {value}")
                print()
            
            # Suspicious headers
            if results["suspicious"]:
                print("[!] SUSPICIOUS HEADERS (should be removed):")
                print()
                for item in results["suspicious"]:
                    print(f"  [{item['severity']}] {item['header']}: {item['value']}")
                    print(f"      {item['description']}")
                    print(f"      → {item['recommendation']}")
                    print()
                    self.findings.append(item)
            
            # Summary
            total_issues = len(results["missing"]) + len(results["suspicious"])
            
            print("=" * 60)
            print(f"[*] Summary:")
            print(f"    Missing security headers: {len(results['missing'])}")
            print(f"    Suspicious headers: {len(results['suspicious'])}")
            print(f"    Present security headers: {len(results['present'])}")
            print(f"    Total issues: {total_issues}")
            
            # Save results
            if self.output:
                with open(self.output, 'w') as f:
                    f.write(f"# Security Header Analysis for {target}\n\n")
                    
                    f.write("## Missing Security Headers\n\n")
                    for item in results["missing"]:
                        f.write(f"### [{item['severity']}] {item['header']}\n")
                        f.write(f"{item['description']}\n\n")
                        f.write(f"**Recommendation:** {item['recommendation']}\n\n")
                    
                    f.write("## Suspicious Headers\n\n")
                    for item in results["suspicious"]:
                        f.write(f"### [{item['severity']}] {item['header']}\n")
                        f.write(f"Value: {item['value']}\n\n")
                        f.write(f"**Recommendation:** {item['recommendation']}\n\n")
            
            return results
            
        except requests.exceptions.Timeout:
            print("[!] Error: Request timed out")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error: {e}")
        
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Roger Headers - HTTP security header analyzer for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-o", "--output", help="Output results to file")
    
    args = parser.parse_args()
    
    scanner = RogerHeaders(
        target=args.target,
        quiet=args.quiet,
        output=args.output
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()