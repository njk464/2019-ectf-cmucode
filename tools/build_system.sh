#!/bin/bash
cd /home/vagrant/MES/Arty-Z7-10/components/ext_sources/u-boot-ectf && \
ARCH=arm CROSS_COMPILE=/opt/pkg/petalinux/tools/linux-i386/gcc-arm-linux-gnueabi/bin/arm-linux-gnueabihf- make zynq_ectf_defconfig && \
ARCH=arm CROSS_COMPILE=/opt/pkg/petalinux/tools/linux-i386/gcc-arm-linux-gnueabi/bin/arm-linux-gnueabihf- make && \
cp ./u-boot /home/vagrant/MES/Arty-Z7-10/images/linux/u-boot.elf