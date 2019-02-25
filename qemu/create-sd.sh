#!/bin/bash

set -e

# create an sdcard image (1.0G)
echo "Creating raw sdcard.img ..."
dd if=/dev/zero of=sdcard.img count=512 bs=2M

# Create a loopback device for raw image
echo "Attaching it to a loopback block device ..."
DEVICE=$(losetup -f)
sudo losetup -fP sdcard.img

# create two partitions
echo "Partitioning the loopback device ... "
sudo sfdisk --force $DEVICE < sdcard-part.sfdisk

# create ext4 partition 2 for games (ignore partition 1)
echo "Creating ext4 filesystem table in partition 2 ... "
sudo mkfs.ext4 ${DEVICE}p2

# mount and copy the game
echo "Mounting and copying the provisioned games to the partition 2"
sudo mkdir -p /mnt/qemu/games
sudo mount -o loop ${DEVICE}p2 /mnt/qemu/games
sudo cp -r /home/vagrant/MES/tools/files/generated/games/* /mnt/qemu/games/

# unmount and remove loopback device
sudo umount /mnt/qemu/games
sudo losetup -d /dev/loop0




