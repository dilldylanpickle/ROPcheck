#!/bin/bash

if [ "$1" = "uninstall" ]; then
    # Remove script file from /usr/local/bin
    sudo rm /usr/local/bin/ROPcheck

    # Remove PATH modification from .bashrc
    sed -i '/\/usr\/local\/bin/d' "$HOME/.bashrc"

    echo "[*] ROPcheck has been uninstalled. [*]"
    exit 0
fi

# Install dependencies
sudo apt-get update
sudo apt install python3-pip
sudo -H python3 -m pip install ROPgadget

# Copy script file to /usr/local/bin
sudo cp ROPcheck.bash /usr/local/bin/ROPcheck
sudo chmod +x /usr/local/bin/ROPcheck

# Add /usr/local/bin to PATH
if ! grep -q "/usr/local/bin" "$HOME/.bashrc"; then
    echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
    echo "Added /usr/local/bin to PATH"
fi

echo "[*] ROPcheck is now installed. You can use it by running 'ROPcheck' in the terminal. [*]"
echo "[*] To uninstall, run 'bash ROPcheck.bash uninstall' in the directory where you installed ROPcheck. [*]"