# XSS & Auth‑Bypass Automation Tool

A Python CLI that automates:
- Reflected, Stored, and DOM XSS detection  
- Forced‑browsing / authorization‑bypass scanning via wordlist  

## Usage

```bash
./xss_tool.py detect-xss 'https://example.com/page?param=1'
./xss_tool.py detect-dom 'https://example.com'
./xss_tool.py detect-stored 'https://example.com/form' --data 'field1=value1'
./xss_tool.py detect-auth-bypass 'https://example.com/admin' --paths ./common_paths.txt
