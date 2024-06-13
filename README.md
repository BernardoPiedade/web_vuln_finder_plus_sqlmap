# web_vuln_finder_plus_sqlmap

This scanner uses sqlmap and automatically tries to exploit xss vulnerabilities if found.

# Dependencies

    pip install requests beautifulsoup4

    sqlmap is also necessary

If you don't want to use sqlmap nor want to automatically exploit xss, then use this scanner instead: https://github.com/BernardoPiedade/web_vuln_finder/tree/main

# Usage

    python web_vuln_scanner.py <URL> --log custom_log.txt
