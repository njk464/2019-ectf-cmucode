# Emulating zynq 7000 SoC board in qemu
Follow the instructions to create qemu machine emulator for loading u-boot/mesh and linux kernel.

Note: Run `petalinuxenv` in the shell before running `qemu` or `petalinux-config`. Ensure petalinux environment is set for every new shell session.

## Known Issues
  * When the linux kernel is loaded, an i2c driver sends a timout message to dmesg (stdout) every 5 seconds. This message is printed out on the serial console which makes it hard to type shell commands, since the error messages fill up the screen. 

## Setting SDCARD Image file
  * Run the shell script `./create-sd.sh` to create an sdcard raw image file - `sdcard.img`. The script will copy the games from `/home/vagrant/MES/Arty-Z7-10/tools/files/generated/games/` folder. 

## Launch Qemu
  * Ensure u-boot, linux kernel and the device tree is built using provisionSystem.py. Check if the following files exists:
    * `/home/vagrant/MES/Arty-Z7-10/images/linux/u-boot.elf`
    * `/home/vagrant/MES/Arty-Z7-10/images/linux/image.ub`
    * `/home/vagrant/MES/Arty-Z7-10/images/linux/system.dtb`
  * Start qemu by running the `./start-qemu.sh`. 

## Petalinux config (in case of spi error)
  * Checking out this branch should inherit the changes to petalinux config. If QEMU/U-BOOT THOWS AN SPI ERROR ON THE SCREEN, follow the below steps and rebuild the kernel and dtb (run the provisionSystem.py again).
    1. cd /home/vagrant/MES/Arty-Z7-10
    2. petalinux-config -c u-boot
    3. select: Device Drivers -> SPI flash support -> STMICRO SPI flash support (press y to select) 
    4. save and exit

# Run GDB with QEMU 
Before starting, make sure to set the petalinux environment variables using `petalinuxenv`. Run qemu by passing the `gdb` as the first argument. 

```bash
~/MES/qemu> ./start-qemu.sh gdb
```
Launch `arm-linux-gnueabihf-gdb` client to attach to the qemu gdb server which is listening to the port 1234. 

```bash
~/MES> arm-linux-gnueabihf-gdb 

(gdb) target remote localhost:1234

(gdb) add-symbol-file ~/MES/Arty-Z7-10/images/linux/u-boot.elf 0x1fb35000
add symbol table from file "/home/vagrant/MES/Arty-Z7-10/images/linux/u-boot.elf" 
at .text_addr = 0x1fb35000 (y or n): y
Reading symbols from /home/vagrant/MES/Arty-Z7-10/images/linux/u-boot.elf ...done

(gdb)b mesh_loop
(gdb)c
```

*** 

[source](https://draskodraskovic.wordpress.com/2012/05/27/debugging-u-boot-in-qemu-2/)

