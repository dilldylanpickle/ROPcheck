#!/bin/bash

# Remove ROPcheck script from /usr/local/bin
sudo rm /usr/local/bin/ROPcheck

# Remove PATH modification from .bashrc
if grep -q "export PATH=\$PATH:/path/to/ROPcheck_" "$HOME/.bashrc"; then
  sed -i 's#export PATH=\$PATH:/path/to/ROPcheck##' "$HOME/.bashrc"
fi

if grep -q "export PATH=\$PATH:/path/to/ROPcheck" "$HOME/.bash_profile"; then
  sed -i 's#export PATH=\$PATH:/path/to/ROPcheck##' "$HOME/.bash_profile"
fi

echo ""
echo "[*] ROPcheck has been uninstalled. [*]"