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

    

    def generate_hashes(self):
        pass

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

