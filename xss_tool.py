#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urljoin, urlparse, parse_qsl

# Default XSS payload
DEFAULT_PAYLOAD = '<script>alert(1);</script>'

class XSSScanner:
    def __init__(self, url, session=None, payload=DEFAULT_PAYLOAD):
        self.url = url
        self.session = session or requests.Session()
        self.payload = payload

    def detect_reflected(self):
        parsed = urlparse(self.url)
        params = dict(parse_qsl(parsed.query))
        vulnerable = []
        for key in params:
            test_params = params.copy()
            test_params[key] = self.payload
            test_url = parsed._replace(query="").geturl() + '?' + '&'.join(f"{k}={v}" for k,v in test_params.items())
            resp = self.session.get(test_url)
            if self.payload in resp.text:
                vulnerable.append((key, test_url))
        return vulnerable

    def detect_stored(self, form_action=None, form_data=None):
        action = form_action or self.url
        data = form_data or {}
        for field in data:
            data[field] = data.get(field, '') + self.payload
        self.session.post(action, data=data)
        resp = self.session.get(self.url)
        return self.payload in resp.text

    def detect_dom(self):
        resp = self.session.get(self.url)
        dom_code = resp.text
        sinks = ['innerHTML', 'document.write', 'eval(', 'location.href']
        return [sink for sink in sinks if sink in dom_code]

class AuthBypassScanner:
    def __init__(self, base_url, session=None, paths_file=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.paths_file = paths_file or []

    def load_paths(self):
        with open(self.paths_file) as f:
            return [line.strip() for line in f if line.strip()]

    def detect_forced_browsing(self):
        accessible = []
        for path in self.load_paths():
            url = f"{self.base_url}/{path.lstrip('/')}"
            resp = self.session.get(url, allow_redirects=False)
            if resp.status_code == 200:
                accessible.append(url)
        return accessible

    def report(self, accessible):
        print("[!] Forced browsing accessible URLs:")
        for url in accessible:
            print(f"    - {url}")

def main():
    parser = argparse.ArgumentParser(description="XSS & Auth Bypass Automation Tool")
    subparsers = parser.add_subparsers(dest='command')

    det_parser = subparsers.add_parser('detect-xss', help='Detect XSS vulnerabilities')
    det_parser.add_argument('url', help='Target URL for XSS detection')
    det_parser.add_argument('--payload', help='Custom XSS payload', default=DEFAULT_PAYLOAD)

    dom_parser = subparsers.add_parser('detect-dom', help='Detect potential DOM XSS sinks')
    dom_parser.add_argument('url', help='Target URL for DOM analysis')

    sto_parser = subparsers.add_parser('detect-stored', help='Detect stored XSS')
    sto_parser.add_argument('url', help='URL of page with a form')
    sto_parser.add_argument('--data', nargs='*', help='Field=value pairs for form', default=[])

    auth_parser = subparsers.add_parser('detect-auth-bypass', help='Detect authorization bypass via forced browsing')
    auth_parser.add_argument('url', help='Base URL of the web app')
    auth_parser.add_argument('--paths', help='File with paths to test', required=True)

    args = parser.parse_args()

    if args.command == 'detect-xss':
        scanner = XSSScanner(args.url, payload=args.payload)
        reflected = scanner.detect_reflected()
        print("Reflected XSS on params:")
        for param, test_url in reflected:
            print(f"    - Param: {param} => {test_url}")

    elif args.command == 'detect-dom':
        scanner = XSSScanner(args.url)
        sinks = scanner.detect_dom()
        print("DOM sinks found:")
        for sink in sinks:
            print(f"    - {sink}")

    elif args.command == 'detect-stored':
        data = dict(item.split('=',1) for item in args.data)
        scanner = XSSScanner(args.url)
        found = scanner.detect_stored(form_data=data)
        print("Stored XSS detected!" if found else "No stored XSS found.")

    elif args.command == 'detect-auth-bypass':
        scanner = AuthBypassScanner(args.url, paths_file=args.paths)
        accessible = scanner.detect_forced_browsing()
        if accessible:
            scanner.report(accessible)
        else:
            print("No accessible paths detected via forced browsing.")

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
