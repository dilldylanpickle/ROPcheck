#!/usr/bin/env python3

# Import necessary modules
import os
import subprocess
import time
import re

# Import custom python modules that will be included in setup.py
import pyfiglet
from tabulate import tabulate
from termcolor import colored

# Get the current working directory
dir = os.getcwd()

# Check if there are any executables in the current directory that are executable
if len([f for f in os.listdir(dir) if os.path.isfile(os.path.join(dir, f)) and os.access(os.path.join(dir, f), os.X_OK)]) == 0:
    print(colored(f"[-] Error: No executables found in {dir}\n", "red"))
    exit(1)

# Define a function called 'get_bitness' that takes a filename as input
def get_bitness(file):
    # Use the 'file' command to determine the bitness of the binary
    output = subprocess.check_output(['file', '-b', file]).decode()
    
    # If the output contains the string '32-bit', return '32-bit'
    if '32-bit' in output:
        return '32-bit'
    # If the output contains the string '64-bit', return '64-bit'
    elif '64-bit' in output:
        return '64-bit'
    else:
        return None

# Define a function called 'find_libc' that takes a filename as input
def find_libc(file):
    bitness = get_bitness(file)
    
    # If the binary is not an ELF file, print an error message and return None
    if not bitness:
        print(colored(f"[-] Error: {file} is not an ELF binary\n", "red"))
        return None

    # If the binary is 32-bit or 64-bit, use the 'ldd' command to get the path of the libc file
    if bitness in ["32-bit", "64-bit"]:
        output = subprocess.check_output(['ldd', file]).decode()
        libc_line = None
        for line in output.splitlines():
            if 'libc.so' in line:
                libc_line = line
                break
        if not libc_line:
            print(colored(f"[-] Error: libc not found in {file}\n", "red"))
            return None

        # Use a regular expression to extract the base address of the libc file
        match = re.search(r'\(0x([0-9a-f]+)\)$', libc_line)
        if match:
            libc_base = match.group(1)
        else:
            print(colored(f"[-] Error: libc base address not found in {file}\n", "red"))
            return None
    else:
        # If the binary is not 32-bit or 64-bit, print an error message and return None
        print(colored(f"[-] Error: {file} is not a 32-bit or 64-bit binary\n", "red"))
        return None

    # Return the base address of the libc file
    return libc_base

# Define a function called 'find_system_address' that takes a filename as input
def find_system_address(file):
    bitness = get_bitness(file)
    system_address = None

    if not bitness:
        print(colored(f"[-] Error: {file} is not an ELF binary\n", "red"))
        return None

    # If the binary is 32-bit or 64-bit, use the 'ldd' command to get the path of the libc file
    if bitness in ["32-bit", "64-bit"]:
        output = subprocess.check_output(['ldd', file]).decode()
        libc_path = None
        for line in output.splitlines():
            if 'libc.so' in line:
                libc_path = line.split()[2].strip('()')
                break
        if not libc_path:
            print(colored(f"[-] Error: libc not found in {file}\n", "red"))
            return None

        # Use the 'readelf' command to get the symbol table of the libc file, and search for the 'system' function
        output = subprocess.check_output(['readelf', '-s', libc_path]).decode()
        system_line = None
        for line in output.splitlines():
            if re.search(r'\bsystem@@GLIBC_', line):
                system_line = line
                break
        if not system_line:
            print(colored(f"[-] Error: system not found in libc\n", "red"))
            return None

        # Use a regular expression to extract the address of the 'system' function from the symbol table
        match = re.search(r'^\s*\d+:\s+([\da-f]+)\s+\d+\s+\w+\s+\w+\s+\w+\s+\d+\s+system@@GLIBC_', system_line)
        if match:
            system_address = match.group(1)
    else:
        print(colored(f"[-] Error: {file} is not a 32-bit or 64-bit binary\n", "red"))
        return None

    return system_address

# Define a function called 'find_binsh' that takes a filename as input
def find_binsh(file):
    bitness = get_bitness(file)

    if not bitness:
        print(colored(f"[-] Error: {file} is not an ELF binary\n", "red"))
        return None

    # Define a list of possible libc paths based on the bitness of the binary
    if bitness == "32-bit":
        libc_paths = ["/lib32/libc.so.6", "/usr/lib32/libc.so.6"]
    elif bitness == "64-bit":
        libc_paths = ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib64/libc.so.6"]
    else:
        print(colored(f"[-] Error: {file} is not a 32-bit or 64-bit binary\n", "red"))
        return None

    # Loop through the possible libc paths and check if the file exists
    for libc_path in libc_paths:
        if os.path.exists(libc_path):
            # If the file exists, use the 'strings' command to get the output of the file as a string
            output = subprocess.check_output(['strings', '-a', '-t', 'x', libc_path]).decode()
            
            # Use the 'search_for_binsh' function to search the output for the string '/bin/sh'
            binsh = search_for_binsh(output)
            if binsh:
                break

    if not binsh:
        print(colored(f"[-] Error: /bin/sh not found in libc\n", "red"))
        return None

    return binsh

# Definea function called "search_for_binsh" that searches for the line that contains"/bin/sh"
def search_for_binsh(output):
    for line in output.splitlines():
        if "/bin/sh" in line:
            return line.split()[0]
    return None

# Define a function called 'find_gadgets' that takes a filename as input
def find_gadgets(file):
    bitness = get_bitness(file)
    
    # Define two lists of gadget names, one for 32-bit binaries and one for 64-bit binaries
    gadget_names = ["pop eax ; ret", "pop edi ; ret", "pop esi ; ret", "pop edx ; ret", "pop esp ; ret"]
    gadget_names_64 = ["pop rax ; ret", "pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret", "pop rsp ; ret"]
    
    gadget_names_to_use = gadget_names_64 if bitness == '64-bit' else gadget_names
    
    # Call the 'get_gadget_addresses' function with the list of gadget names and the binary filename as arguments
    gadget_addresses = get_gadget_addresses(file, gadget_names_to_use)
    
    if not gadget_addresses:
        print(colored(f"[-] Error: failed to find rop gadgets\n", "red"))
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

# Animate the ROPcheck process for each function the program calls
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
    # Print ROPcheck logo using pyfiglet library
    print(pyfiglet.figlet_format("ROPcheck"))
    time.sleep(0.69)

    # Define the headers for the output table and an empty list to store the data
    headers = ["File Name", "libc base address", "system address", "/bin/sh address", "Gadgets"]
    data = []

    # Iterate over each executable file in the current directory and process it
    for file in os.listdir(dir):
        filepath = os.path.join(dir, file)
        if os.access(filepath, os.X_OK) and os.path.isfile(filepath):
            # Print a message indicating which binary is being processed
            print(f"[*] Processing the {file} binary for ROP ", end="")

            # Animate a loading message using the animate_processing() function
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

            # Find the libc base address for the binary
            libc_base = find_libc(filepath)
            if libc_base:
                # Format the libc base address as a string and print a success message
                libc_base = f"0x{libc_base}"
                print(f"[+] Found libc base address for {file} ", end="")
                animate_processing()

                # Find the system address for the binary
                system_address = find_system_address(filepath)
                if system_address:
                    # Format the system address as a string and print a success message
                    system_address = f"0x{system_address}"
                    print(f"[+] Found system address for {file} ", end="")
                    animate_processing()

                    # Find the /bin/sh address for the binary
                    binsh_address = find_binsh(filepath)
                    if binsh_address:
                        # Format the /bin/sh address as a string and print a success message
                        binsh_address = f"0x{binsh_address}"
                        print(f"[+] Found /bin/sh address for {file} ", end="")
                        animate_processing()

                        # Find ROP gadgets for the binary and format them as a string
                        gadget_addresses = find_gadgets(filepath)
                        if gadget_addresses:
                            gadgets = "\n".join(gadget_addresses.keys())
                            print(f"[+] Found ROP gadgets for {file} ", end="")
                            animate_processing()
                            print()
                        else:
                            # If no gadgets are found, set the string to "N/A" and print a message
                            gadgets = colored("N/A", "red")
                    else:
                        # If /bin/sh is not found, set the string to "N/A" and print a message
                        binsh_address = colored("N/A", "red")
                        gadgets = colored("N/A", "red")
                else:
                    # If system() is not found, set the strings to "N/A" and print a message
                    system_address = colored("N/A", "red")
                    binsh_address = colored("N/A", "red")
                    gadgets = colored("N/A", "red")
            else:
                # If libc is not found, set all strings to "N/A" and print a message
                libc_base = colored("N/A", "red")
                system_address = colored
                binsh_address = colored("N/A", "red")
                gadgets = colored("N/A", "red")

             # Add the binary file information to the 'data' list as a new row
            data.append([file, libc_base, system_address, binsh_address, gadgets])

    # Sets the style and color for the table that will print out the information
    tablefmt = "grid"
    na_rep = colored("N/A", "red")
    # Print the 'data' list as a table, using the 'tabulate' function
    print(tabulate(data, headers=headers, tablefmt=tablefmt, missingval=na_rep))

# If this script is being run as the main program, call the 'main' function
if __name__ == "__main__":
    main()
