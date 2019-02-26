#!/bin/bash

set -e 

FLAGS=""

if [ ! -f /home/vagrant/MES/Arty-Z7-10/images/linux/u-boot.elf ]; then
  echo "Cannot find the u-boot kernel"; exit 1;
elif [ ! -f /home/vagrant/MES/Arty-Z7-10/images/linux/system.dtb ]; then
  echo "Cannot find the system device tree"; exit 1;
elif [ ! -f /home/vagrant/MES/Arty-Z7-10/images/linux/image.ub ]; then 
  echo "Cannot find the system kernel"; exit 1;
elif [ ! -f ./sdcard.img ]; then
  echo "Cannot find the sdcard image"; exit 1;
fi

if [ "$1" == "gdb" ]; then
  FLAGS="${FLAGS} -s -S"
  shift
fi

source /opt/pkg/petalinux/settings.sh

qemu-system-aarch64 -M arm-generic-fdt-7series -machine linux=on -serial stdio -display none -kernel /home/vagrant/MES/Arty-Z7-10/images/linux/u-boot.elf -dtb /home/vagrant/MES/Arty-Z7-10/images/linux/system.dtb -drive file=./sdcard.img,if=sd,format=raw -device loader,file=/home/vagrant/MES/Arty-Z7-10/images/linux/image.ub,addr=0x10000000 ${FLAGS}
