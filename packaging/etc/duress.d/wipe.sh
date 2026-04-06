#!/bin/bash

# Remove all key slots from active volumes
cryptsetup erase /dev/mmcblk1p2 --batch-mode

# Remove LUKS header
cryptsetup luksHeaderWipe /dev/mmcblk1p2 --batch-mode
cryptsetup luksHeaderBackup /dev/mmcblk1p2 --header-backup-file /dev/null 2>/dev/null

# Overwrite the beginning of the partition with random data
dd if=/dev/urandom of=/dev/mmcblk1p2 bs=512 count=8192 conv=notrunc

# Power off the system
systemctl poweroff


