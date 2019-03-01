#!/usr/bin/python3

import os
import subprocess
import re
import argparse
import base64
import pysodium
import bcrypt

# Path to the mesh_users header file
mesh_users_fn = os.environ["ECTF_UBOOT"] + "/include/mesh_users.h"
# Path to the default_games header file
default_games_hpath = os.environ["ECTF_UBOOT"] + "/include/default_games.h"
# Path where generated files will go
gen_path = "files/generated"
# File name for the bif file
system_image_fn = "SystemImage.bif"
# File name for the factory secrets
factory_secrets_fn = "FactorySecrets.txt"
# Path to secrets header file
secret_header_fn = os.environ["ECTF_UBOOT"] + "/include/secret.h"
# number of rounds bcrypt uses
bcrypt_rounds=10

def gen_key_nonce():
    key = pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    return (key, nonce)

def gen_keypair():
    pk, sk = pysodium.crypto_sign_keypair()
    f = open("pk.out", "wb")
    f.write(pk)
    f.close()
    f = open("sk.out", "wb")
    f.write(sk)
    f.close()
    return pk, sk

def validate_users(lines):
    """Validate that the users data is formatted properly and return a list
    of tuples of users and pins.
    TODO: Check this regular expression
    lines: list of strings from a users.txt file with newlines removed
    """
    # Regular expression to ensure that there is a username and an 8 digit pin
    reg = r'^\s*(\w+)\s+(\d{8})\s*$'
    users = []
    for line in lines:
        for m in [re.match(reg, line)]:
            if m:
                hashed_pass = bcrypt.hashpw(m.group(2).encode('utf-8'), bcrypt.gensalt(rounds=bcrypt_rounds)).decode("utf-8")
                users.append((m.group(1), hashed_pass))

    # return a list of tuples of (username, hashed_pin)
    return users

def factory_secrets_users(lines):
    """Validate that the users data is formatted properly and return a list
    of tuples of users and pins.
    TODO: Check this regular expression
    lines: list of strings from a users.txt file with newlines removed
    """
    # Regular expression to ensure that there is a username and an 8 digit pin
    reg = r'^\s*(\w+)\s+(\d{8})\s*$'
    lines = [(m.group(1), m.group(2)) for line in lines
             for m in [re.match(reg, line)] if m]

    # return a list of tuples of (username, pin)
    return lines

def write_mesh_users_h(users, f):
    """Write user inforation to a header file

    users: list of tuples of (username, pin)
    f: open file object for the header file to be written
    """
    # write users to header file
    f.write("""
/*
* This is an automatically generated file by provisionSystem.py
*
*
*/

#ifndef __MESH_USERS_H__
#define __MESH_USERS_H__

#include <mesh.h>

#define NUM_MESH_USERS {num_users}

struct MeshUser {{
    char username[MAX_USERNAME_LENGTH + 1];
    char hash[61];
    char pin[MAX_PIN_LENGTH + 1];
}};

static struct MeshUser mesh_users[] = {{
""".format(num_users=len(users)))

    for (user, hashpw) in users:
        data = '    {.username="%s", .hash="%s"},\n' % (user, hashpw)
        f.write(data)

    f.write("""
}};

static char* default_hash = "{}";

#endif /* __MESH_USERS_H__ */
""".format(users[len(users)-1][1]))


def write_mesh_default_h(default_txt_path, header_path):
    """Turn the default.txt into a C header file for MESH

    default_txt_path: path to the default.txt file to be read from
    header_path: path to the C header file to be written
    """

    # Open the file and read into a variable
    with open(default_txt_path, 'r') as f:
        lines = f.read().split('\n')

    # Base string to write
    s = """
/*
* This is an automatically generated file by provisionSystem.py
*
*
*/

#ifndef __MESH_DEFAULT_TXT_H__
#define __MESH_DEFAULT_TXT_H__

"""

    # Write the number of default games
    s += "#define NUM_DEFAULT_GAMES %s\n" % sum(1 for line in lines if line)
    # For each line, write the game information
    s += """
static char* default_games[] = {
"""
    for line in lines:
        # Ignore blank lines
        if not line:
            continue
        # Split on space
        line = line.split()
        # Game name is before the first space
        game_name = line[0]
        # Split what's after the first space (version information) into
        # major.minor
        line = line[1].split('.')
        major = line[0]
        minor = line[1]
        # Write the information as gamename-vmajor.minor to the header file
        s += "    \"%s-v%s.%s\",\n" % (game_name, major, minor)

    s += """
};

#endif /* __MESH_DEFAULT_TXT_H__ */
"""
    with open(header_path, 'w') as f:
        f.write(s)


def build_images():
    """Create MES.bin using the petalinux tools"""
    print("Building Images... this may take a while!")
    # Source the petalinux env, then cd into the source code directory.
    # Clean the project (since petalinux doesn't always build correctly
    # depending on what files you have modified; for example configs)
    # then build everything
    subprocess.check_call(["/bin/bash", "-i", "-c", "petalinuxenv > /dev/null && cd $ECTF_PETALINUX/Arty-Z7-10/ && petalinux-build -x distclean && petalinux-build"])
    print("Done Building Images to %s" % (os.environ["ECTF_PETALINUX"] + '/Arty-Z7-10/images'))


def write_system_image_bif(f):
    """Write the bif file

    f: open file to write the bif to
    """
    f.write("""
MITRE_Entertainment_System: {{
    [bootloader] /home/vagrant/MES/tools/files/zynq_fsbl.elf
    // Participants Bitstream
    {path}/Arty-Z7-10/images/linux/Arty_Z7_10_wrapper.bit
    // Paritcipants Images
    {path}/Arty-Z7-10/images/linux/u-boot.elf
    [load=0x10000000] {path}/Arty-Z7-10/images/linux/image.ub
}}
    """.format(path=os.environ["ECTF_PETALINUX"]))


def write_factory_secrets(users, f, h):
    """Write any factory secrets. The reference implementation has none
    users: tuples of the users 
    f: open file to write the factory secrets to
    h: open file to write data to pass along to shell
    """
    flag = 0
    salt_array = []
    if len(users) > 32:
        print("Max Users Exceeded. Only 32 users are permitted.")
        exit()
    
    for user in users:
        if user == 'demo':
            flag = 1
        salt = os.urandom(pysodium.crypto_pwhash_SALTBYTES)
        f.write(user[0]+ ' '+ user[1] + ' '+ base64.b64encode(salt).decode() + '\n')
        salt_array.append([user[0], salt])

    if flag == 0:
        salt = os.urandom(pysodium.crypto_pwhash_SALTBYTES)
        f.write('demo'+ ' '+ '00000000' + ' '+ base64.b64encode(salt).decode() + '\n')
        salt_array.append(['demo', salt])
    
    header_key, header_nonce = gen_key_nonce()
    flash_key, flash_nonce = gen_key_nonce()
    pk, sk = gen_keypair()
    f.write(base64.b64encode(header_key).decode() + '\n')
    f.write(base64.b64encode(sk).decode() + '\n')

    pk_bytes = ""
    for i in pk[:-1]:
        pk_bytes += '0x%x, ' % i
    pk_bytes += '0x%x' % pk[-1]

    header_key_bytes = ""
    for i in header_key[:-1]:
        header_key_bytes += '0x%x, ' % i
    header_key_bytes += '0x%x' % header_key[-1]

    flash_key_bytes = ""
    for i in flash_key[:-1]:
        flash_key_bytes += '0x%x, ' % i
    flash_key_bytes += '0x%x' % flash_key[-1]

    header_nonce_bytes = ""
    for i in header_nonce[:-1]:
        header_nonce_bytes += '0x%x, ' % i
    header_nonce_bytes += '0x%x' % header_nonce[-1]

    s = """
/*
* This is an automatically generated file by provisionSystem.py
*
*
*/

#ifndef __SECRET_H__
#define __SECRET_H__

#include "mesh.h"
#define SALT_LENGTH 16

static char sign_public_key[] = {"""
    s += pk_bytes
    s += """};\nstatic char header_key[] = {"""
    s += header_key_bytes
    s += """};\nstatic char flash_key[] = {"""
    s += flash_key_bytes
    s += "};\nstatic char salt[MAX_NUM_USERS][SALT_LENGTH] = {\n"

    for entry in salt_array[:-1]:
        salt_bytes = ""
        for i in entry[1][:-1]:
            salt_bytes += '0x%x, ' % i
        salt_bytes += '0x%x' % entry[1][-1]
        s += "\t{" + salt_bytes + "},\n"
    entry = salt_array[-1]
    salt_bytes = ""
    for i in entry[1][:-1]:
        salt_bytes += '0x%x, ' % i
    salt_bytes += '0x%x' % entry[1][-1]
    s += "\t{" + salt_bytes + "}\n};\n"


    s += "static char users[MAX_NUM_USERS][MAX_USERNAME_LENGTH] = {"
    for entry in salt_array[:-1]:
        s += "\n\t{\"" + entry[0] + "\"},"
    entry = salt_array[-1]
    s += "\n\t{\"" + entry[0] + "\"}\n};"
    s += """
#endif /* __SECRET_H__ */
"""

    h.write(s)

def main():
    # Argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('USERS_FILE', help="""
    This a text file that includes username and passwords in a MITRE
    defined format

    # comment
    User1 12345678
    User2 12345678
        """)
    parser.add_argument('DEFAULT_FILE', help="""
    This a text file that includes game name and version of games
    that must be installed by defalut in order for the system to boot.

    # comment
    game_foo 1.1
    game_bar 2.0
        """)
    args = parser.parse_args()

    # open arg file
    try:
        f_mesh_users_in = open(args.USERS_FILE, "r")
    except Exception as e:
        print("Unable to open users text file %s: %s" % (args.USERS_FILE, e,))
        exit(2)

    # Create the folder where the generated files will go
    # (any any parent folders)
    subprocess.check_call("mkdir -p " + gen_path, shell=True)
    # Try to open each file that we'll need to write to, report error messages
    try:
        f_mesh_users_out = open(mesh_users_fn, "w+")
    except Exception as e:
        print("Unable to open generated users header file: %s" % (e,))
        exit(2)
    try:
        f_system_image = open(os.path.join(gen_path, system_image_fn), "w+")
    except Exception as e:
        print("Unable to open %s: %s" % (system_image_fn, e,))
        exit(2)
    try:
        f_factory_secrets = open(os.path.join(gen_path, factory_secrets_fn), "w+")
    except Exception as e:
        print("Unable to open %s: %s" % (factory_secrets_fn, e,))
        exit(2)

    try:
        f_secret_header = open(os.path.join(gen_path, secret_header_fn), "w+")
    except Exception as e:
        print("Unable to open secret header file: %s" % (e,))
        exit(2)

    # Read in all of the user information into a list and strip newlines
    lines = [line.rstrip('\n') for line in f_mesh_users_in]

    try:
        secret_users = factory_secrets_users(lines)
    except Exception as e:
            print("Users text file is misformated.")
            exit(2)
            
    # parse user strings
    try:
        users = validate_users(lines)
    except Exception as e:
            print("Users text file is misformated.")
            exit(2)

    # Add the demo user, which must always exist, per the rules
    demo_hash = bcrypt.hashpw("00000000".encode('utf-8'), bcrypt.gensalt(rounds=bcrypt_rounds)).decode("utf-8")
    users.append(("demo", demo_hash))
    # write mesh users to uboot header
    write_mesh_users_h(users, f_mesh_users_out)
    f_mesh_users_out.close()
    print("Generated mesh_users.h file: %s" % (mesh_users_fn))

    # Write the default games file
    write_mesh_default_h(args.DEFAULT_FILE, default_games_hpath)
    print("Generated default_games.h file")
    
    # write factory secrets
    write_factory_secrets(secret_users, f_factory_secrets, f_secret_header)
    f_factory_secrets.close()
    f_secret_header.close()
    print("Generated FactorySecrets file: %s\nGenerated SecretHeader file: %s" % (os.path.join(gen_path, factory_secrets_fn), secret_header_fn))
    
    # build MES.bin # Doesn't actually create the file? Makes that in package
    build_images()

    # write system image bif
    write_system_image_bif(f_system_image)
    f_system_image.close()
    print("Generated SystemImage file: %s" % (os.path.join(gen_path, system_image_fn)))

    exit(0)


if __name__ == '__main__':
    main()
