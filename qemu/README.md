# Emulating zynq 7000 SoC board in qemu
Follow the instructions to a create qemu machine emulator to load u-boot/mesh and linux kernel.

Note: Run `petalinuxenv` in the shell before running the`qemu` or `petalinux-config`. Ensure petalinux environment is set for every new session.

## Known Issues
  * When the linux kernel is loaded, a i2c driver sends a timout message to dmesg (stdout) every 5 seconds. The message is printed out on the serial output which makes it hard to type shell commands since the error message fills up the screen. 

## Setting up SDCARD Image file
  * Run the shell script create-sd.sh to create sdcard raw image file - sdcard.img. The script will copy the games from /home/vagrant/MES/Arty-Z7-10/tools/files/generated/games/ folder. 

## Launch Qemu
  * Ensure u-boot, linux kernel and the device tree is built using provisionSystem.py. Check if the following files exists:
    * /home/vagrant/MES/Arty-Z7-10/images/linux/u-boot.elf
    * /home/vagrant/MES/Arty-Z7-10/images/linux/image.ub
    * /home/vagrant/MES/Arty-Z7-10/images/linux/system.dtb
  * Start qemu by running the `start-qemu.sh`. 

## Petalinux config
  * Checking out this branch should inherit the changes to petalinux config. IF QEMU/U-BOOT THOWS AN SPI ERROR ON THE SCREEN, follow the below steps and rebuild the kernel and dtb (run the provisionSystem.py again).
    1. cd /home/vagrant/MES/Arty-Z7-10
    2. petalinux-config -c u-boot
    3. select: Device Drivers -> SPI flash support -> STMICRO SPI flash support (press y to select) 
    4. save and exit

