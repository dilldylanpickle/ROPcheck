#!/bin/bash

dir=$PWD


if [[ ! $(find "$dir" -maxdepth 1 -type f -executable | wc -l) -gt 0 ]]; then
    echo "Error: No executables found in $dir"
    exit 1
fi

get_bitness() {
    local file=$1
    echo $(file "$file" | grep -o 'ELF [0-9]*-bit' | cut -d' ' -f2)
}

find_libc() {
    local file=$1
    local bitness=$(get_bitness "$file")
    local libc=

    if [ -z "$bitness" ]; then
        echo "Error: $file is not an ELF binary"
        return 1
    fi

    case $bitness in
        "32-bit"|"64-bit")
            libc=$(ldd "$file" | grep libc.so | awk '{print $4}' | tr -d '()' | tr -d '\n')
            ;;
        *)
            echo "Error: $file is not a 32-bit or 64-bit binary"
            return 1
            ;;
    esac

    if [ -z "$libc" ]; then
        echo "Error: libc not found in $file"
        return 1
    fi

    echo "$libc"
}

find_system() {
    local file=$1
    local bitness=$(get_bitness "$file")
    local system=

    if [ -z "$bitness" ]; then
        echo "Error: $file is not an ELF binary"
        return 1
    fi

    case $bitness in
        "32-bit")
            if [ -e "/lib32/libc.so.6" ]; then
                system=$(readelf -s /lib32/libc.so.6 | grep system | awk '/system/{line=$4} END{print $2}')
            elif [ -e "/usr/lib32/libc.so.6" ]; then
                system=$(readelf -s /usr/lib32/libc.so.6 | grep system | awk '/system/{line=$4} END{print $2}')
            else
                echo "Error: libc.so.6 not found in /lib32 or /usr/lib32"
                return 1
            fi
            ;;
        "64-bit")
            if [ -e "/lib/x86_64-linux-gnu/libc.so.6" ]; then
                system=$(readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system | awk '/system/{line=$4} END{print $2}')
            elif [ -e "/usr/lib64/libc.so.6" ]; then
                system=$(readelf -s /usr/lib64/libc.so.6 | grep system | awk '/system/{line=$4} END{print $2}')
            else
                echo "Error: libc.so.6 not found in /lib/x86_64-linux-gnu or /usr/lib64"
                return 1
            fi
            ;;
        *)
            echo "Error: $file is not a 32-bit or 64-bit binary"
            return 1
            ;;
    esac

    if [ -z "$system" ]; then
        echo "Error: system not found in libc"
        return 1
    fi

    echo "$system"
}

find_binsh() {
    local file=$1
    local bitness=$(get_bitness "$file")
    local binsh=

    if [ -z "$bitness" ]; then
        echo "Error: $file is not an ELF binary"
        return 1
    fi

    case $bitness in
        "32-bit")
            if [ -e "/lib32/libc.so.6" ]; then
                binsh=$(strings -a -t x /lib32/libc.so.6 | grep /bin/sh | awk '/system/{line=$4} END{print $1}')
            elif [ -e "/usr/lib32/libc.so.6" ]; then
                binsh=$(strings -a -t x /usr/lib32/libc.so.6 | grep /bin/sh | awk '/system/{line=$4} END{print $1}')
            else
                echo "Error: libc.so.6 not found in /lib32 or /usr/lib32"
                return 1
            fi
            ;;
        "64-bit")
            if [ -e "/lib/x86_64-linux-gnu/libc.so.6" ]; then
                binsh=$(strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh | awk '/system/{line=$4} END{print $1}')
            elif [ -e "/usr/lib64/libc.so.6" ]; then
                binsh=$(strings -a -t x /usr/lib64/libc.so.6 | grep /bin/sh | awk '/system/{line=$4} END{print $1}')
            else
                echo "Error: libc.so.6 not found in /lib/x86_64-linux-gnu or /usr/lib64"
                return 1
            fi
            ;;
        *)
            echo "Error: $file is not a 32-bit or 64-bit binary"
            return 1
            ;;
    esac

    if [ -z "$binsh" ]; then
        echo "Error: /bin/sh not found in libc"
        return 1
    fi

    echo "$binsh"
}

find_gadgets() {
    local file="$1"
    local bitness=$(get_bitness "$file")
    local pop_regs=("rdi" "rsi" "rdx" "rax")
    local gadget=
    local gadgets_found=false
    
    case $(readelf -h "$file" | grep 'Class:' | awk '{print $2}') in
    "ELF32")
        pop_regs=("edi" "esi" "edx" "ecx")
        ;;
    "ELF64")
        pop_regs=("rdi" "rsi" "rdx" "rcx")
        ;;
    *)
        printf "Error: %s is not a 32-bit or 64-bit binary\n" "$file"
        return 1
        ;;
    esac

    for reg in "${pop_regs[@]}"; do
        if [ "$reg" = "rax" ] && [ "$bitness" = "32-bit" ]; then
            continue
        fi
        gadget=$(ROPgadget --binary "$file" --only "pop|ret" | grep "pop $reg ; ret" | cut -d' ' -f1)
        if [ -n "$gadget" ]; then
            if [ "$gadgets_found" = false ]; then
                printf "[*] These rop gadgets were found in %s\n" "${file##*/}"
                gadgets_found=true
            fi
            printf "pop %s address: %27s\n" "$reg" "$gadget"
        fi
    done
    
    if [ "$gadgets_found" = false ]; then
        printf "[*] No useful rop gadgets found in %s\n" "${file##*/}"
    fi
}


for file in "$dir"/*;
do
    if [[ -x "$file" && ! -d "$file" ]]; then
        printf "[*] Processing the %s binary for ROP\n" "${file##*/}"

        libc=$(find_libc "$file") || continue
        system=$(find_system "$file") || continue
        binsh=$(find_binsh "$file") || continue

        printf "libc address: %30s\n" "$libc"
        printf "system address: %28s\n" "0x$system"
        printf "/bin/sh address: %27s\n\n" "0x$binsh"
        find_gadgets "$file"
        echo ""
    fi
done
