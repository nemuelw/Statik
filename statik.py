# Author : Nemuel Wainaina
# Script to automate Static Malware Analysis

import binary2strings as b2s
import filetype
import hashlib
import os
import requests
import sys

from colorama import init, Fore

class MalwareSample:
    
    def __init__(self, file) -> None:
        self.sample = file

    def get_file_info(self):
        pass

    def generate_hashes(self):
        with open(self.sample, "rb") as f:
            content = f.read()
        self.md5 = hashlib.md5(content).hexdigest()
        self.sha1 = hashlib.sha1(content).hexdigest()
        self.sha256 = hashlib.sha256(content).hexdigest()
        self.sha512 = hashlib.sha512(content).hexdigest()

    def vt_check(self):
        pass

    def analyze(self):
        pass

if __name__ == "__main__":
    init()
    GREEN = Fore.GREEN
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

