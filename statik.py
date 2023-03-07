# Author : Nemuel Wainaina
# Script to automate Static Malware Analysis

import binary2strings as b2s
import filetype
import hashlib
import json
import os
import requests
import sys
import urllib.request

from colorama import init, Fore

def print_header(title):
    title = "[*] " + title
    print(f"{BLUE} {title} {RESET}")
    print("{} {} {}".format(BLUE, '-'*len(title), RESET))

def print_info(name, info):
    print("{} {} {}: {}".format(YELLOW, name, RESET, info))

def has_internet_access():
    try:
        urllib.request.urlopen("https://google.com")
        return True
    except:
        return False

def load_api_key():
    with open("key.json", "r") as f:
        content = f.read()
    return json.loads(content)['api_key']

class VTScan:

    def __init__(self, sample, api_key) -> None:
        self.headers = {
            "x-apikey": api_key,
            "User-Agent": "Statik v.1.0.0",
            "Accept-Encoding": "gzip,deflate"
        }

    def upload(self):
        if has_internet_access():
            pass
        else:
            print("{} [!]{} Can't reach VirusTotal (No internet connection)".format(RED, RESET))

    def print_results(self):
        pass

class MalwareSample:
    
    def __init__(self, file) -> None:
        self.sample = file

    def get_basic_file_info(self):
        file_name = os.path.basename(self.sample)
        if "." in file_name:
            tmp = file_name.split(".")
            name = tmp[0]
            ext = tmp[1]
        else:
            name = file_name
            ext = None
        size = os.stat(self.sample).st_size
        kind = filetype.guess(self.sample)
        print_info("File name", name)
        print_info("Extension", ext)
        print_info("File size", size)
        if kind is None:
            kind = "Could not guess the file type"
        print_info("File type", kind)

    def generate_hashes(self):
        with open(self.sample, "rb") as f:
            self.binary = f.read()
        self.md5 = hashlib.md5(self.binary).hexdigest()
        self.sha1 = hashlib.sha1(self.binary).hexdigest()
        self.sha256 = hashlib.sha256(self.binary).hexdigest()
        self.sha512 = hashlib.sha512(self.binary).hexdigest()
        print_info("MD5", "\n "+self.md5)
        print_info("SHA1", "\n "+self.sha1)
        print_info("SHA256", "\n "+self.sha256)
        print_info("SHA512", "\n "+self.sha512)

    def extract_strings(self):
        strings = b2s.extract_all_strings(self.binary, min_chars=8, only_interesting=False)
        for string in strings:
            print(" " + string[0])

    def vt_check(self):
        api_key = load_api_key()
        vt = VTScan(self.sample, api_key)
        vt.upload()

    def analyze(self):
        print_header("Basic File Info : ")
        self.get_basic_file_info()
        print()
        print_header("File Hashes : ")
        self.generate_hashes()
        print()
        print_header("Extracted Strings : ")
        self.extract_strings()
        print()
        print_header("VirusTotal Check : ")
        self.vt_check()

if __name__ == "__main__":
    init()
    GREEN = Fore.GREEN
    BLUE = Fore.BLUE
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    GRAY = Fore.LIGHTBLACK_EX
    RESET = Fore.RESET

    args = sys.argv
    if len(args) != 2:
        print(f"{RED} [!] {RESET} Syntax : python3 statik.py <sample_file>")
        exit(1)
    
    file = sys.argv[1]
    if not os.path.exists(file):
        print(f"{RED} [!] {RESET} The file {file} does not exist")
        exit(1)
    if not os.path.isfile(file):
        print(f"{RED} [!] {RESET} The provided path does not point to a file")
        exit(1)

    sample = MalwareSample(file=file)
    sample.analyze()
