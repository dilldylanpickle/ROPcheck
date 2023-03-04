#!/usr/bin/env python3

# ROPcheck - a tool for identifying ROP gadgets in binaries
# Created by dilldylanpickle on 2023-03-03
# GitHub: https://github.com/dilldylanpickle
#
# ROPcheck is a Python tool that displays useful information for performing return oriented programming
# It can be used for binary exploitation and vulnerability research.
#
# As the creator of this tool, I wrote the initial code and have been actively maintaining it.
# The tool has been tested on Linux and macOS operating systems (Also supported on WSL).
# Any questions or issues with the tool can be directed to me via GitHub.
#
# Version 2.0 - 2023-03-03
#
# Dependencies:
#   - Python 3.8.10
#   - ROPgadget (https://github.com/JonathanSalwan/ROPgadget)
#   - PyFiglet (https://github.com/pwaller/pyfiglet)
#   - Tabulate (https://pypi.org/project/tabulate/)
#   - Termcolor (https://pypi.org/project/termcolor/)
#   - Progress (https://pypi.org/project/progress/)
# 
# Example Usage: $ Ropcheck
#
# This tool is licensed under the MIT License. See LICENSE file for more information.

# Import the necessary modules for the ROPcheck tool
import os              # for accessing operating system functionality
import subprocess      # for running shell commands
import time            # for adding delays
import re              # for regular expression matching
import glob            # for finding files that match a pattern

# Import third-party Python modules that will be included in setup.py
import pyfiglet        # for generating ASCII art text
from tabulate import tabulate  # for displaying tabular data in the console
from termcolor import colored  # for adding color to terminal output
from progress.bar import Bar   # for displaying progress bars during long-running tasks

# Get the current working directory
dir = os.getcwd()

# Get a list of all executable files in the current directory
executable_files = glob.glob(os.path.join(dir, '*'), recursive=False)
executable_files = [f for f in executable_files if os.access(f, os.X_OK)]

# Check if any executable files were found
if not executable_files:
    print(colored(f"[-] Error: No executable files found in {dir}\n", "red"))
    exit(1)

# Define a function called 'get_bitness' that takes a filename as input and returns its bitness (32-bit or 64-bit)
def get_bitness(file):
    try:
        # Use the 'file' command to determine the bitness of the binary
        output = subprocess.check_output(['file', '-b', file]).decode()
        
        # If the output contains the string '32-bit', return '32-bit'
        if '32-bit' in output:
            return '32-bit'
        # If the output contains the string '64-bit', return '64-bit'
        elif '64-bit' in output:
            return '64-bit'
        else:
            raise ValueError(f"Invalid bitness: {output}")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to get the bitness of {file}: {e}")

# Define a function called 'get_bitness' that takes a filename as input and returns a libc base address

def find_libc(file):
    # Check the bitness of the binary file
    try:
        bitness = get_bitness(file)
    except (ValueError, RuntimeError) as e:
        # Print an error message if the bitness cannot be determined
        print(colored(f"[-] Error: {e}", "red"))
        return None

    if bitness not in ["32-bit", "64-bit"]:
        # Print an error message if the binary file is not 32-bit or 64-bit
        print(colored(f"[-] Error: {file} is not a 32-bit or 64-bit binary", "red"))
        return None

    try:
        # Use the ldd command to get the path of the libc file
        output = subprocess.check_output(['ldd', '-r', file], text=True)
    except subprocess.CalledProcessError as e:
        # Print an error message if ldd command fails
        print(colored(f"[-] Error: {e}", "red"))
        return None

    # Find the line containing 'libc.so' and extract the base address
    libc_line = next((line for line in output.splitlines() if 'libc.so' in line), None)
    if not libc_line:
        # Print an error message if libc is not found in the output of ldd command
        print(colored(f"[-] Error: libc not found in {file}", "red"))
        return None

    start = libc_line.rfind('(') + 1
    end = libc_line.rfind(')')
    libc_base = libc_line[start:end]

    return libc_base

# Define a function called 'find_system_address' that takes a filename as input and returns a system() address
def find_system_address(file):

    # Get the bitness of the binary file
    bitness = get_bitness(file)
    system_address = None

    # Check if the file is an ELF binary
    if not bitness:
        raise ValueError(f"{file} is not an ELF binary")

    # Check if the binary is either 32-bit or 64-bit
    if bitness not in ["32-bit", "64-bit"]:
        raise ValueError(f"{file} is not a 32-bit or 64-bit binary")

    try:
        # Run the ldd command to get the path of the libc file
        output = subprocess.check_output(['ldd', file], text=True)
    except subprocess.CalledProcessError:
        raise RuntimeError(f"ldd failed for {file}")

    libc_path = None
    # Find the line containing 'libc.so' and extract its path
    for line in output.splitlines():
        if 'libc.so' in line:
            libc_path = line.split()[2].strip('()')
            break

    # If the path to libc is not found, raise an error
    if not libc_path:
        raise RuntimeError(f"libc not found in {file}")

    try:
        # Run the readelf command to get the symbol table of the libc file
        output = subprocess.check_output(['readelf', '-s', libc_path], text=True)
    except subprocess.CalledProcessError:
        raise RuntimeError(f"readelf failed for {libc_path}")

    system_address = None
    # Find the address of the 'system' function in the symbol table
    for line in output.splitlines():
        match = re.match(r'^\s*\d+:\s+(?P<addr>[\da-f]+)\s+\d+\s+\w+\s+\w+\s+\w+\s+\d+\s+system@@GLIBC_', line)
        if match:
            system_address = match.group('addr')
            break

    # If the 'system' function address is not found, raise an error
    if not system_address:
        raise RuntimeError(f"system not found in {libc_path}")

    return system_address

# Define a function called 'find_binsh' that takes a filename as input and returns the /bin/sh address
def find_binsh(file):
    try:
        # Get the bitness of the binary file
        bitness = get_bitness(file)

        if not bitness:
            # Raise an error if the file is not an ELF binary
            print(colored(f"[-] Error: {file} is not an ELF binary\n", "red"))
            return None

        # Define a list of possible libc paths based on the bitness of the binary
        if bitness == "32-bit":
            libc_paths = [f"/lib{i}/libc.so.6" for i in ["/i386-linux-gnu", "/i686-linux-gnu", "32", ""]]
            libc_paths += [f"/usr/lib{i}/libc.so.6" for i in ["/i386-linux-gnu", "/i686-linux-gnu", "32", ""]]
        elif bitness == "64-bit":
            libc_paths = [f"/lib{x}/libc.so.6" for x in ["/x86_64-linux-gnu", "64", ""]]
            libc_paths += [f"/usr/lib{x}/libc.so.6" for x in ["/x86_64-linux-gnu", "64", ""]]
        else:
            # Raise an error if the file is not a 32-bit or 64-bit binary
            print(colored(f"[-] Error: {file} is not a 32-bit or 64-bit binary\n", "red"))
            return None

        # Loop through the possible libc paths and check if the file exists
        for libc_path in libc_paths:
            if os.path.exists(libc_path):
                # Use the 'strings' command to get the output of the file as a string
                output = subprocess.check_output(['strings', '-a', '-t', 'x', libc_path], text=True)

                # Search the output for the string '/bin/sh'
                for line in output.splitlines():
                    if "/bin/sh" in line:
                        # Return the address of '/bin/sh' if found
                        return line.split()[0]

        # Raise an error if '/bin/sh' was not found in the libc file
        print(colored(f"[-] Error: /bin/sh not found in libc\n", "red"))
        return None
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Raise an error if the 'strings' command failed or the libc file was not found
        print(colored(f"[-] Error: failed to find /bin/sh in {file}\n", "red"))
        return None

# Define a function called 'find_useful_functions' that takes a filename as input and returns useful function addresses
def find_useful_functions(file):

    try:
        # Get the bitness of the binary
        bitness = get_bitness(file)

        # Create a dictionary to store the addresses of useful functions
        useful_functions = {}

        # Define a list of possible function names to search for
        function_names = ["system", "execve", "mprotect", "exit", "chroot", "setuid", "setgid", "dup2"]

        # Get the libc file(s) used by the binary
        ldd_output = subprocess.check_output(['ldd', file]).decode()
        libc_files = re.findall(r'(/lib\S+|/usr/lib\S+)', ldd_output)

        # Search for the function addresses in the binary and libc file(s)
        for f in [file] + libc_files:
            with Bar(f"[+] Searching for functions in {f}", max=len(function_names), suffix='%(percent)d%%') as bar:
                for name in function_names:
                    # Use objdump and grep to find the function addresses
                    objdump = subprocess.Popen(['objdump', '-D', f], stdout=subprocess.PIPE)
                    grep = subprocess.Popen(['grep', '-m', '1', '-w', name + "@"], stdin=objdump.stdout, stdout=subprocess.PIPE)
                    objdump.stdout.close()
                    output = grep.communicate()[0].decode().strip()

                    if output:
                        # If a function address is found, store it in the dictionary
                        address = output.split()[0]
                        useful_functions[name] = address

                    bar.next()

        if not useful_functions:
            # If no useful functions are found, print an error message and return None
            print(colored(f"[-] Error: failed to find useful functions\n", "red"))
            return None

        # Convert the addresses to a readable format
        for func, addr in useful_functions.items():
            addr_without_leading_zeros = addr.lstrip('0')
            if not addr_without_leading_zeros:
                addr_without_leading_zeros = '0'
            useful_functions[func] = f"0x{addr_without_leading_zeros}"

        return useful_functions

    except (subprocess.CalledProcessError, FileNotFoundError):
        # If an error occurs while searching for functions, print an error message and return None
        print(colored(f"[-] Error: failed to find useful functions in {file}\n", "red"))
        return None

# Define a function called 'find_gadgets' that takes a filename as input and returns ROP gadget addresses
def find_gadgets(filepath):
    try:
        # Get the bitness of the binary
        bitness = get_bitness(filepath)

        # Use ROPgadget to find pop/ret gadgets in the binary
        output = subprocess.check_output(f"ROPgadget --binary {filepath} --only 'pop|ret' --nojop --nosys", shell=True, stderr=subprocess.STDOUT)
        output = output.decode().split("\n")
    except subprocess.CalledProcessError as e:
        # If an error occurs while running ROPgadget, print an error message and return None
        print(colored(f"[-] Error running ROPgadget: {e.output.decode()}", "red"))
        return None
    except ValueError as e:
        # If an error occurs while parsing the output from ROPgadget, print an error message and return None
        print(colored(str(e), "red"))
        return None

    # Define a list of possible gadget names based on the bitness of the binary
    if bitness == "32-bit":
        pop_registers = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'esp']
    else:
        pop_registers = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rsp']

    # Create a dictionary to store the addresses and names of gadgets
    gadget_addresses = {}

    # Parse the output from ROPgadget to find pop/ret gadgets
    for line in output:
        # Ignore lines that don't start with an address
        line = line.strip()
        if not line.startswith('0x'):
            continue

        # Split the line into the address and gadget name
        parts = line.split(' : ')
        if len(parts) != 2:
            continue
        address, gadget = parts

        # Ignore gadgets that aren't pop instructions
        if not gadget.startswith('pop'):
            continue

        # Replace 'pop ;' with 'pop ??? ;' to handle malformed gadgets
        if 'pop ;' in gadget:
            gadget = gadget.replace('pop ;', 'pop ??? ;')

        # Ignore gadgets that don't pop a valid register
        if not gadget.split()[1] in pop_registers:
            continue

        # Store the address and name of the gadget in the dictionary
        gadget_addresses[address] = gadget

    return gadget_addresses

# Define a function called 'find_stack_pivot' that takes a filename as input and returns stack pivot gadget addresses
def find_stack_pivot(file):
    try:
        # Get the bitness of the binary
        bitness = get_bitness(file)

        # Create a dictionary to store the addresses and names of stack pivot gadgets
        stack_pivot_gadgets = {}

        # Define a list of possible gadget names based on the bitness of the binary
        if bitness == "32-bit":
            gadget_names = ["xchg esp, eax ; ret"]
            register_name = "esp"
        elif bitness == "64-bit":
            gadget_names = ["xchg rax, rsp ; ret", "xchg rsp, rax ; ret", "mov esp, eax ; ret"]
            register_name = "rsp"
        else:
            # If the binary is not 32-bit or 64-bit, print an error message and return None
            print(colored(f"[-] Error: {file} is not a 32-bit or 64-bit binary", "red"))
            return None

        # Create a dictionary to store the addresses and names of stack pivot gadgets
        gadget_addresses = {}

        # Use ROPgadget to find gadgets in the binary
        output = subprocess.check_output(['ROPgadget', '--binary', file]).decode()

        # Parse the output from ROPgadget to find stack pivot gadgets
        for line in output.split('\n'):
            for name in gadget_names:
                if name in line:
                    # Extract the address of the gadget
                    match = re.search(r'0x[0-9a-fA-F]+', line)
                    if match:
                        addr = match.group(0)
                        # Check if the gadget swaps the stack pointer with the specified register
                        if register_name in line:
                            gadget_name = line.split(':')[1].strip()
                            gadget_addresses[addr] = gadget_name

        return gadget_addresses

    except (subprocess.CalledProcessError, FileNotFoundError):
        # If an error occurs while searching for gadgets, print an error message and return None
        print(colored(f"[-] Error: failed to find stack pivot gadgets in {file}\n", "red"))
        return None

# Animate the ROPcheck process for each function the program calls
def animate_processing():
    # Loop through a sequence of characters to create an animation
    for i in range(5):
        time.sleep(0.05)
        if i % 4 == 0:
            # Clear the line if this is the first frame
            print("", end="\r")
        elif i % 4 == 1:
            # Show a forward slash if this is the second frame
            print("[/]", end="\r")
        elif i % 4 == 2:
            # Show a hyphen if this is the third frame
            print("[-]", end="\r")
        elif i % 4 == 3:
            # Show a backslash if this is the fourth frame
            print("[\\]", end="\r")
    # Print a final message to indicate that the animation is complete
    print("[+]")
    
# Define the main function
def main():
    # Print ROPcheck logo using pyfiglet library
    print(pyfiglet.figlet_format("ROPcheck"))
    time.sleep(0.69)

    # Define the headers for the output tables and empty lists to store the data
    binary_headers = ["File Name", "Libc base address", "System() address", "/bin/sh address", "Syscall addresses"]
    binary_data = []
    rop_headers = ["File Name", "ROP Gadget addresses", "Stack Pivot addresses"]
    rop_data = []

    # Iterate over each executable file in the current directory and process it
    for file in os.listdir(dir):
        filepath = os.path.join(dir, file)
        if os.access(filepath, os.X_OK) and os.path.isfile(filepath):
            # Print a message indicating which binary is being processed
            print(f"[*] Processing the {file} ELF binary ", end="")

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
                libc_base = format(int(libc_base, 16), "x")
                print(f"[+] Found libc base address for {file}", end="")
                animate_processing()

                # Find the system address for the binary
                system_address = find_system_address(filepath)
                if system_address:
                    # Format the system address as a string and print a success message
                    system_address = format(int(system_address, 16), "x")
                    print(f"[+] Found system address for {file}", end="")
                    animate_processing()

                    # Find the /bin/sh address for the binary
                    binsh_address = find_binsh(filepath)
                    if binsh_address:
                        # Format the /bin/sh address as a string and print a success message
                        binsh_address = format(int(binsh_address, 16), "x")
                        print(f"[+] Found /bin/sh address for {file}", end="")
                        animate_processing()

                        # Find other useful functions for the binary and format them as a string
                        useful_functions = find_useful_functions(filepath)
                        if useful_functions:
                            functions = "\n".join([f"{func}: 0x{int(addr.rstrip(':'), 16):x}" for func, addr in useful_functions.items()])
                            print(f"[+] Found system calls for {file} ", end="")
                            animate_processing()

                            # Add the binary file information to the 'binary_data' list as a new row
                            binary_data.append([file, f"0x{int(libc_base, 16):x}", f"0x{int(system_address, 16):x}", f"0x{int(binsh_address, 16):x}", functions])

                            # Modify the gadgets variable to only include the gadget name and its address
                            gadgets = ""
                            gadget_addresses = find_gadgets(filepath)
                            if gadget_addresses:
                                gadgets = "\n".join([f"{gadget.split(':')[0].strip()}: 0x{int(address, 16):x}" for address, gadget in gadget_addresses.items()])
                                print(f"[+] Found ROP gadgets for {file} ", end="")
                                animate_processing()

                                # Find potential stack pivot gadgets for the binary and format them as a string
                                stack_pivot_gadgets = find_stack_pivot(filepath)
                                if stack_pivot_gadgets:
                                    stack_pivot_gadgets_str = "\n".join([f"{gadget}: 0x{int(address, 16):x}" for address, gadget in stack_pivot_gadgets.items()])                       
                                    stack_pivot_gadgets_str = stack_pivot_gadgets_str.replace("xchg rsp, rax ; ret :", "xchg rsp, rax ; ret:").replace("xchg rax, rsp ; ret :", "xchg rax, rsp ; ret:").replace("mov esp, eax ; ret :", "mov esp, eax ; ret:")   
                                    stack_pivot_gadgets_str = stack_pivot_gadgets_str.replace('0x0', '0x')
                                    print(f"[+] Found potential stack pivot gadgets for {file}", end="")
                                    animate_processing()
                                    print()
                                else:
                                    stack_pivot_gadgets_str = colored("N/A", "red")
                                    print(colored(f"[-] No stack pivot gadgets found in {file}", "red"))
                                    print()

                            # Add the binary file information to the 'rop_data' list as a new row
                            rop_data.append([file, gadgets, stack_pivot_gadgets_str])

                        else:
                            # If no gadgets are found, set the string to "N/A" and print a message
                            gadgets = colored("N/A", "red")
                            print(colored(f"[-] No ROP gadgets found in {file}", "red"))
                            rop_data.append([file, gadgets, colored("N/A", "red")])

                    else:
                        # If /bin/sh is not found, set the string to "N/A" and print a message
                        binsh_address = colored("N/A", "red")
                        gadgets = colored("N/A", "red")
                        print(colored(f"[-] /bin/sh not found in {file}", "red"))
                        binary_data.append([file, f"0x{int(libc_base, 16):x}", f"0x{int(system_address, 16):x}", binsh_address, colored("N/A", "red")])
                        rop_data.append([file, gadgets, colored("N/A", "red")])

                else:
                    # If system() is not found, set the strings to "N/A" and print a message
                    system_address = colored("N/A", "red")
                    binsh_address = colored("N/A", "red")
                    gadgets = colored("N/A", "red")
                    print(colored(f"[-] system() not found in {file}", "red"))
                    binary_data.append([file, f"0x{int(libc_base, 16):x}", system_address, binsh_address, colored("N/A", "red")])
                    rop_data.append([file, gadgets, colored("N/A", "red")])

            else:
                # If libc is not found, set all strings to "N/A" and print a message
                libc_base = colored("N/A", "red")
                system_address = colored("N/A", "red")
                binsh_address = colored("N/A", "red")
                gadgets = colored("N/A", "red")
                print(colored(f"[-] libc not found in {file}", "red"))
                binary_data.append([file, libc_base, system_address, binsh_address, colored("N/A", "red")])
                rop_data.append([file, gadgets, colored("N/A", "red")])

    # Sets the style and color for the tables that will print out the information
    tablefmt = "grid"
    na_rep = colored("N/A", "red")

    # Print the 'binary_data' list as a table called 'Binary Information', using the 'tabulate' function
    print(colored("Binary Information", "cyan"))
    print(tabulate(binary_data, headers=binary_headers, tablefmt=tablefmt, missingval=na_rep))
    print()

    # Print the final 'rop_data' list as a table called 'ROP Gadget Information', using the 'tabulate' function
    print(colored("ROP Gadget Information", "cyan"))

    # Print the final 'rop_data' list as a table called 'ROP Gadget Information', using the 'tabulate' function
    print(tabulate(rop_data, headers=rop_headers, tablefmt=tablefmt, missingval=na_rep))
    print()

# If this script is being run as the main program, call the 'main' function
if __name__ == "__main__":
    main()
