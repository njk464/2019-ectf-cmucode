
start ()
{
    echo -e '\033[9;0]' > /dev/tty1

    # enable full ASLR
    echo 2 > /proc/sys/kernel/randomize_va_space

    # we need to decrypt the file to a random file name
    TMP_FILE=`mktemp`
    
    touch $TMP_FILE

    # shell script for drrun stuff
    touch /usr/bin/startup.sh

    echo "#!/bin/sh" >> /usr/bin/startup.sh
    echo "stty -F /dev/ttyPS0 speed 115200" >> /usr/bin/startup.sh
    echo "/usr/share/dynamorio/bin32/drrun -c /usr/share/dynamorio/plugin/libcfiplugin.so -- $TMP_FILE" >> /usr/bin/startup.sh
    
    # create user and set permissions
    adduser ectf --shell /usr/bin/startup.sh --disabled-password --gecos ""

    chown ectf:ectf /usr/bin/startup.sh
    chmod 500 /usr/bin/startup.sh

    # uio stuff
    chmod a+wr /dev/uio*
    a=$(grep mesh_drm /sys/class/uio/uio*/maps/map*/name | cut -d'/' -f5)
    if [ ! -z "$a" ]; then
        mv /dev/$a /dev/mesh_drm
    fi

    chmod 666 /dev/ttyPS0

    # set tty device with correct baud
    stty -F /dev/ttyPS0 speed 115200

    # load the game in ramfs 
    mesh-game-loader $TMP_FILE
    
    # update permissions
    chown ectf:ectf $TMP_FILE
    chmod u+x $TMP_FILE
   
    # login ectf and launch the game
    /bin/login -f ectf
    
    # reboot
    sleep 5
    shutdown -r now
}
stop ()
{
    echo " Stopping..."
}
restart()
{
    stop
    start
}
case "$1" in
    start)
start; ;;
    stop)
    stop; ;;
    restart)
    restart; ;;
    *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1

esac

exit 0
