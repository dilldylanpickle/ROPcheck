#!/usr/bin/env python3

import os
import subprocess
import time
import re

import pyfiglet
from tabulate import tabulate

dir = os.getcwd()

if len([f for f in os.listdir(dir) if os.path.isfile(os.path.join(dir, f)) and os.access(os.path.join(dir, f), os.X_OK)]) == 0:
    print(f"Error: No executables found in {dir}")
    exit(1)

def get_bitness(file):
    output = subprocess.check_output(['file', '-b', file]).decode()
    if '32-bit' in output:
        return '32-bit'
    elif '64-bit' in output:
        return '64-bit'
    else:
        return None

def find_libc(file):
    bitness = get_bitness(file)
    libc_base = None

    if not bitness:
        print(f"Error: {file} is not an ELF binary")
        return None

    if bitness in ["32-bit", "64-bit"]:
        output = subprocess.check_output(['ldd', file]).decode()
        libc_line = None
        for line in output.splitlines():
            if 'libc.so' in line:
                libc_line = line
                break
        if not libc_line:
            print(f"Error: libc not found in {file}")
            return None

        match = re.search(r'\(0x([0-9a-f]+)\)$', libc_line)
        if match:
            libc_base = match.group(1)
        else:
            print(f"Error: libc base address not found in {file}")
            return None
    else:
        print(f"Error: {file} is not a 32-bit or 64-bit binary")
        return None

    return libc_base

def find_system_address(file):
    bitness = get_bitness(file)
    system_address = None

    if not bitness:
        print(f"Error: {file} is not an ELF binary")
        return None

    if bitness in ["32-bit", "64-bit"]:
        output = subprocess.check_output(['ldd', file]).decode()
        libc_path = None
        for line in output.splitlines():
            if 'libc.so' in line:
                libc_path = line.split()[2].strip('()')
                break
        if not libc_path:
            print(f"Error: libc not found in {file}")
            return None

        output = subprocess.check_output(['readelf', '-s', libc_path]).decode()
        system_line = None
        for line in output.splitlines():
            if re.search(r'\bsystem@@GLIBC_', line):
                system_line = line
                break
        if not system_line:
            print(f"Error: system not found in libc")
            return None

        match = re.search(r'^\s*\d+:\s+([\da-f]+)\s+\d+\s+\w+\s+\w+\s+\w+\s+\d+\s+system@@GLIBC_', system_line)
        if match:
            system_address = match.group(1)
    else:
        print(f"Error: {file} is not a 32-bit or 64-bit binary")
        return None

    return system_address

def find_binsh(file):
    bitness = get_bitness(file)
    binsh = None

    if not bitness:
        print(f"Error: {file} is not an ELF binary")
        return None

    if bitness == "32-bit":
        libc_paths = ["/lib32/libc.so.6", "/usr/lib32/libc.so.6"]
    elif bitness == "64-bit":
        libc_paths = ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib64/libc.so.6"]
    else:
        print(f"Error: {file} is not a 32-bit or 64-bit binary")
        return None

    for libc_path in libc_paths:
        if os.path.exists(libc_path):
            output = subprocess.check_output(['strings', '-a', '-t', 'x', libc_path]).decode()
            binsh = search_for_binsh(output)
            if binsh:
                break

    if not binsh:
        print(f"Error: /bin/sh not found in libc")
        return None

    return binsh

def search_for_binsh(output):
    for line in output.splitlines():
        if "/bin/sh" in line:
            return line.split()[0]
    return None

def find_gadgets(file):
    bitness = get_bitness(file)
    gadget_names = ["pop eax ; ret", "pop edi ; ret", "pop esi ; ret", "pop edx ; ret", "pop esp ; ret"]
    gadget_names_64 = ["pop rax ; ret", "pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret", "pop rsp ; ret"]

    if not bitness:
        print(f"Error: {file} is not an ELF binary")
        return None

    gadget_names_to_use = gadget_names_64 if bitness == '64-bit' else gadget_names

    gadget_addresses = get_gadget_addresses(file, gadget_names_to_use)

    if not gadget_addresses:
        print(f"Error: failed to find gadgets in {file}")
        return None

    return gadget_addresses

def get_gadget_addresses(file, gadget_names):
    gadget_addresses = {}

    # Run ROPgadget command and get the output
    output = subprocess.check_output(['ROPgadget', '--binary', file]).decode()

    # Parse the output to extract the gadget addresses
    for line in output.split('\n'):
        for name in gadget_names:
            if name in line:
                match = re.search(r'0x[0-9a-fA-F]+', line)
                if match:
                    gadget_addresses[name] = match.group(0)

    return gadget_addresses

def animate_processing():
    for i in range(5):
        time.sleep(0.05)
        if i % 4 == 0:
            print("", end="\r")
        elif i % 4 == 1:
            print("[/]", end="\r")
        elif i % 4 == 2:
            print("[-]", end="\r")
        elif i % 4 == 3:
            print("[\\]", end="\r")
    print("[+]")

def main():
    print(pyfiglet.figlet_format("ROPcheck"))
    time.sleep(0.69)

    headers = ["File Name", "libc base address", "system address", "/bin/sh address", "Gadgets"]
    data = []

    for file in os.listdir(dir):
        filepath = os.path.join(dir, file)
        if os.access(filepath, os.X_OK) and os.path.isfile(filepath):
            print(f"[*] Processing the {file} binary for ROP ", end="")
            for i in range(15):
                time.sleep(0.05)
                if i % 4 == 0:
                    print("", end="\r")
                elif i % 4 == 1:
                    print("[/]", end="\r")
                elif i % 4 == 2:
                    print("[-]", end="\r")
                elif i % 4 == 3:
                    print("[\\]", end="\r")
            print("[+]")

            libc_base = find_libc(filepath)
            if libc_base:
                libc_base = f"0x{libc_base}"
                print(f"[+] Found libc base address for {file} ", end="")
                animate_processing()

                system_address = find_system_address(filepath)
                if system_address:
                    system_address = f"0x{system_address}"
                    print(f"[+] Found system address for {file} ", end="")
                    animate_processing()

                    binsh_address = find_binsh(filepath)
                    if binsh_address:
                        binsh_address = f"0x{binsh_address}"
                        print(f"[+] Found /bin/sh address for {file} ", end="")
                        animate_processing()

                        gadget_addresses = find_gadgets(filepath)
                        if gadget_addresses:
                            gadgets = "\n".join(gadget_addresses.keys())
                        else:
                            gadgets = "N/A"
                        print(f"[+] Found ROP gadgets for {file} ", end="")
                        animate_processing()
                        print()
                    else:
                        print(f"Error: failed to find /bin/sh address for {file}")
                        binsh_address = "N/A"
                        gadgets = "N/A"
                else:
                    print(f"Error: failed to find system address for {file}")
                    system_address = "N/A"
                    binsh_address = "N/A"
                    gadgets = "N/A"
            else:
                print(f"Error: failed to find libc base address for {file}")
                libc_base = "N/A"
                system_address = "N/A"
                binsh_address = "N/A"
                gadgets = "N/A"

            data.append([file, libc_base, system_address, binsh_address, gadgets])

    print(tabulate(data, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    main()