# linux-anti-recon
Linux anti-reconnaissance kernel module. Mitigates OS fingerprinting and service detection.

## Prerequisites
- Linux kernel version 2.4.x or later
- `sudo apt install build-essential linux-headers-$(uname -r)`

## Commands
- `make` - build module
- `make run` - load module
- dmesg - print kernel log
- `make clean` - unload module and clean directory

## Disclaimer
This is a proof-of-concept, contains hardcoded strings and version identifiers, and may not work on some Linux distributions.
