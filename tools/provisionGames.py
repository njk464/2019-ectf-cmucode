#!/usr/bin/env python3

import os
import argparse
import re
import subprocess
import base64
import pysodium
from struct import pack

# Path to the generated games folder
gen_path = "files/generated/games"

def gen_key_nonce():
    key = pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    return (key, nonce)

def gen_userkey(user, pin, salt, game_name, version):
    password = user.encode() + pin.encode() + game_name.encode() + version.encode() + salt
    key = pysodium.crypto_hash_sha256(password)
    return key

def sign(message, sk):
    signed_message = pysodium.crypto_sign(message, sk)
    return signed_message

def verify_signature(signed_encrypted, pk):
    encrypted = pysodium.crypto_sign_open(signed_encrypted, pk)
    return encrypted

def encrypt(key, nonce, message):
    cipherText = pysodium.crypto_secretbox(message, nonce, key) 
    return cipherText

def encrypt_game_key(user_key, game_key, game_nonce):
    gamekey_nonce = game_key + game_nonce
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    encrypted_gamekey_nonce = pysodium.crypto_secretbox(gamekey_nonce, nonce, user_key) 
    return encrypted_gamekey_nonce, nonce

def encrypt_game(game, gamekey, gamenonce):
    gamepath = game.split()[0]
    gamebin = open(gamepath, 'rb').read()
    encrypted_game = pysodium.crypto_secretbox(gamebin, gamenonce, gamekey)
    return encrypted_game

def encrypt_header(user_array, name, version, game_users, gamekey, gamenonce, header_key, header_nonce):
    header = bytes("version:%s\n" % (version), "utf-8")
    header += bytes("name:%s\n" % (name), "utf-8")
    for user in game_users:
        # find the user data
        found = False
        for user_data in user_array:
            if user == user_data[0]:
                found = True
                break
        if found:
            username = user_data[0]
            user_pin = user_data[1]
            user_salt = user_data[2]
            user_key = gen_userkey(username, user_pin, user_salt, name, version)
            encrypted_gamekey, user_nonce = encrypt_game_key(user_key, gamekey, gamenonce)
            header += user.encode()
            header += ' '.encode()
            header += encrypted_gamekey + user_nonce
    encrypted_header = encrypt(header_key, header_nonce, header)
    # append len i
    print(header)
    header_len = pack('Q', len(encrypted_header))
    print(header_len)
    encrypted_header = header_len + encrypted_header
    return encrypted_header

def provision_game(line, user_array, header_key, header_nonce, sk):
    """Given a line from games.txt, provision a game and write to the
    appropriate directory

    line: string from games.txt to create a game for
    """
    # Regular expression to parse out the necessary parts of the line in the
    # games.txt file. The regular expression works as follows:
    # 1. Match a file name and capture it
    # 2. Skip over any whitespace
    # 3. Match the game name and capture it
    # 4. Skip over whitespace
    # 5. Match the group (major.minor)
    # TODO: Evaluate this as a possible entry point

    reg = r'^\s*([\w\/\-.\_]+)\s+([\w\-.\_]+)\s+(\d+\.\d+|\d+)((?:\s+\w+)+)'
    m = re.match(reg, line)
    if not m:
        return

    # Path to the game
    g_path = m.group(1)
    # Name of the game
    name = m.group(2)
    # Game version
    version = m.group(3)
    # List of users (strings) that are allowed to play this game
    game_users = m.group(4).split()

    # Open the path to the games in binary mode
    # try:
    #     f = open(g_path, "rb")
    # except Exception as e:
    #     print("Error, could not open game: %s" % (e))
    #     exit(1)

    # The output of the game into the file should be:
    # gamename-vmajor.minor
    f_out_name = name + "-v" + version
    # Open the output file in binary mode
    try:
        f_out = open(os.path.join(gen_path, f_out_name), "wb")
    except Exception as e:
        print("Error, could not open game output file: %s" % (e))
        # f.close()
        exit(1)

    # Write the game header to the top of the file
    # The game header takes the form of the version, name, and user information
    # one separate lines, prefaced with the information for what the data is
    # (version, name, users), separated by a colon. User information is space
    # separated
    # For example:
    # version:1.0
    # name:2048
    # users:drew ben lou hunter 

    (gamekey, gamenonce) = gen_key_nonce()
    encrypted_header = encrypt_header(user_array, name, version, game_users, gamekey, gamenonce, header_key, header_nonce)
    encrypted_game = encrypt_game(line, gamekey, gamenonce)
    header_game = encrypted_header + encrypted_game
    signed_file = sign(header_game, sk)
    f_out.write(signed_file)

    # header = bytes("version:%s\n" % (version), "utf-8")
    # header += bytes("name:%s\n" % (name), "utf-8")
    # for user in users:
    #     header = bytes("users:%s\n" % (user), "utf-8")
    # f_out.write(bytes("version:%s\n" % (version), "utf-8"))
    # f_out.write(bytes("name:%s\n" % (name), "utf-8"))
    # f_out.write(bytes("users:%s\n" % (" ".join(users)), "utf-8"))

    # # Read in the binary source
    # g_src = f.read()
    # # Write the binary source
    # while g_src:
    #     f_out.write(g_src)
    #     g_src = f.read()

    # Close the files
    f_out.close()
    # f.close()

    print("    %s -> %s" % (g_path, os.path.join(gen_path, f_out_name)))

def load_factory_secrets(f):
    lines = [line.rstrip('\n') for line in f]
    sk = lines[-1]
    sk = base64.b64decode(sk)
    header_nonce = lines[-2]
    header_nonce = base64.b64decode(header_nonce)
    header_key = lines[-3]
    header_key = base64.b64decode(header_key)
    array = []
    for user in lines[:-3]:
        array.append(user.split(' '))
    for user in array:
        user[2] = base64.b64decode(user[2])

    return array, header_key, header_nonce, sk

def main():
    # argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('factory_secrets',
                        help=("This file is the FactorySecrets.txt file "
                              "generated by provisionSystem.py"))
    parser.add_argument('games',
                        help=("A text file containing game information in a "
                              "MITRE defined format."))
    args = parser.parse_args()

    # open factory secrets
    try:
        f_factory_secrets = open(args.factory_secrets, "r")
    except Exception as e:
        print("Couldn't open file %s: %s" % (args.factory_secrets), (e))
        exit(2)

    # Open the games file
    try:
        f_games = open(args.games, "r")
    except Exception as e:
        print("Couldn't open file %s" % (args.games))
        f_factory_secrets.close() # Doesn't close otherwise?
        exit(2)
    
    user_array, header_key, header_nonce, sk = load_factory_secrets(f_factory_secrets)

    subprocess.check_call("mkdir -p %s" % (gen_path), shell=True)

    print("Provision Games...")

    # Provision each line in the games file
    for line in f_games:
        provision_game(line, user_array, header_key, header_nonce, sk)

    print("Done Provision Games")

    exit(0)


if __name__ == '__main__':
    main()
