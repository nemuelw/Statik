# Author : Nemuel Wainaina
# Script to automate Static Malware Analysis

import hashlib
import os
import sys

from colorama import init, Fore

class MalwareSample:
    
    def __init__(self, file) -> None:
        self.sample = file

    def generate_hashes(self):
        pass

    def vt_check(self):
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