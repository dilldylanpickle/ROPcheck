#!/bin/bash

# Check if the current OS is Ubuntu or Arch Linux
if [ -f /etc/apt/sources.list ]; then
    PACKAGE_MANAGER="apt"
elif [ -f /etc/pacman.conf ]; then
    PACKAGE_MANAGER="pacman"
else
    echo "Unsupported operating system."
    exit 1
fi

if [ "$1" = "uninstall" ]; then
    # Remove script file from /usr/local/bin
    sudo rm /usr/local/bin/ROPcheck

    # Remove PATH modification from .bashrc
    if [ "$PACKAGE_MANAGER" = "apt" ]; then
        sed -i '//usr/local/bin/d' "$HOME/.bashrc"
    elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
        sed -i '//usr/local/bin/d' "$HOME/.bashrc"
        sed -i '//usr/local/bin/d' "$HOME/.bash_profile"
    fi

    echo "[] ROPcheck has been uninstalled. []"
    exit 0
fi

# Install dependencies
if [ "$PACKAGE_MANAGER" = "apt" ]; then
    sudo apt-get update
    sudo apt install python3-pip
    sudo apt-get install dos2unix
elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
    sudo pacman -Syu
    sudo pacman -S python-pip
    sudo pacman -S dos2unix
fi
sudo -H python3 -m pip install ROPgadget pyfiglet tabulate termcolor

# Clear out any line terminators from Windows Subsystem for Linux
dos2unix ROPcheck.py

# Copy main file to /usr/local/bin
sudo cp ROPcheck.py /usr/local/bin/ROPcheck
sudo chmod +x /usr/local/bin/ROPcheck

# Add /usr/local/bin to PATH
if ! grep -q "/usr/local/bin" "$HOME/.bashrc"; then
    echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
    if [ "$PACKAGE_MANAGER" = "pacman" ]; then
        echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bash_profile
    fi
    echo "Added /usr/local/bin to PATH"
fi

echo ""
echo "[] ROPcheck is now installed. You can use it by running 'ROPcheck' in the terminal. []"
echo "[] To uninstall, run 'bash ROPcheck.bash uninstall' in the directory where you installed ROPcheck. []"
