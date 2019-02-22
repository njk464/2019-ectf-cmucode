import base64
import os
import re
import pickle
from struct import *
import pysodium
import array

def generate_and_encrypt(message):
    # This must be kept secret, this is the combination to your safe
    #key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    key = pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
    #print(len(key))
    # Th`/gis is your safe, you can use it to encrypt or decrypt messages
    #box = nacl.secret.SecretBox(key)

    # This is our message to send, it must be a bytestring as SecretBox will
    #   treat it as just a binary blob of data.
    #f = open('demo_files/2048', 'rb')
    #message = f.read()
    #print(len(message))
    # This is a nonce, it *MUST* only be used once, but it is not considered
    #   secret and can be transmitted or stored alongside the ciphertext. A
    #   good source of nonces are just sequences of 24 random bytes.
    #nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    #print(len(nonce))
    #encrypted = box.encrypt(message, nonce)
    cipherText = pysodium.crypto_secretbox(message, nonce, key) 
    #print("cipherText: 0x"+",0x".join("{:02x}".format(ord(c)) for c in cipherText))
    #print(len(cipherText))
    (message, nonce, key)
    #print(len(cipherText))
    # out_file.write(cipherText)

    return cipherText, key, nonce

def gen_key_nonce():
    key = pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    return (key, nonce)

def encrypt_game_key(user_key, game_key, game_nonce):
    #print(game_key)
    #print(game_nonce)
    gamekey_nonce = game_key + game_nonce
    #print(gamekey_nonce)
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    encrypted_gamekey_nonce = pysodium.crypto_secretbox(gamekey_nonce, nonce, user_key) 
    #print(nonce)
 #print(encrypted_gamekey_nonce)
    return encrypted_gamekey_nonce, nonce

def decrypt(key, nonce, cipherText):
    plaintext = pysodium.crypto_secretbox_open(cipherText, nonce, key)
    return plaintext

def encrypt(key, nonce, message):
    cipherText = pysodium.crypto_secretbox(message, nonce, key) 
    return cipherText

def sign_game(message, pk_file):
    pk, sk = pysodium.crypto_sign_keypair()
    pk_file.write(pk)
    #message = b'THIS IS A HEADER' + message
    signed_encrypted_game = pysodium.crypto_sign(message, sk)
    return signed_encrypted_game, pk

def verify_signature(signed_encrypted, pk):
    #print("signed_encrypted: 0x"+",0x".join("{:02x}".format(ord(c)) for c in signed_encrypted))
    #print(len(signed_encrypted))
    encrypted = pysodium.crypto_sign_open(signed_encrypted, pk)
    #print("cipherText: 0x"+",0x".join("{:02x}".format(ord(c)) for c in cipherText))
    return encrypted

# Given data, generats a key via sha256
def gen_userkey(user, pin, salt, game_name, version):
    password = user.encode() + pin.encode() + game_name.encode() + version.encode() + salt
    key = pysodium.crypto_hash_sha256(password)
    return key

def encrypt_header(users, game, gamekey, gamenonce, key, nonce):
    #print(game)
    name = game[1]
    version = game[2]
    game_users = game[3]
    out_name = name + "-v" + version
    header = bytes("version:%s\n" % (version), "utf-8")
    header += bytes("name:%s\n" % (name), "utf-8")
    for user in game[3]:
        # find the user data
        found = False
        for user_data in users:
            if user == user_data[0]:
                found = True
                break
        if found:
            username = user_data[0]
            user_pin = user_data[1]
            user_salt = base64.b64decode(user_data[2])
            user_key = gen_userkey(username, user_pin, user_salt, name, version)
            encrypted_gamekey, game_nonce = encrypt_game_key(user_key, gamekey, gamenonce)
            b64_encoded_gamekey = base64.b64encode(encrypted_gamekey)
            b64_encoded_nonce = base64.b64encode(game_nonce)
            header += bytes("users:%s %s %s\n" % (user, b64_encoded_gamekey, b64_encoded_nonce), "utf-8")
    encrypted_header = encrypt(key, nonce, header)
    # append len 
    header_len = pack('Q', len(encrypted_header))
    encrypted_header = header_len + encrypted_header
    return out_name, encrypted_header

def gen_keypair():
    pk, sk = pysodium.crypto_sign_keypair()
    return pk, sk

# Encrypt the game binary
def encrypt_game(game, gamekey, gamenonce):
    gamepath = game[0]
    gamebin = open(gamepath, 'rb').read()
    encrypted_game = pysodium.crypto_secretbox(gamebin, gamenonce, gamekey)
    return encrypted_game

# everything is getting signed with the same public key, right?
def sign(message, sk):
    signed_message = pysodium.crypto_sign(message, sk)
    return signed_message

# PK is a standard secret. 
# So is the user nonce???
# For now, hardcode the user nonce. 
def encrypt_sign_file(users, game, sk, key, nonce, pk):
    (gamekey, gamenonce) = gen_key_nonce()
    (out_name, encrypted_header) = encrypt_header(users, game, gamekey, gamenonce, key, nonce)
    encrypted_game = encrypt_game(game, gamekey, gamenonce)
    header_game = encrypted_header + encrypted_game
    signed_file = sign(header_game, sk)
    header_game = verify_signature(signed_file, pk)
    fp = open(out_name,'wb')
    fp.write(signed_file)
    fp.close()

# validates the user input, and splits the data into a triple
def validate_users(lines):
    reg = r'^\s*(\w+)\s+(\d{8})\s+([A-Za-z0-9\+\/=]{24})\s*$'
    users = [(m.group(1), m.group(2), m.group(3)) for line in lines
                for m in [re.match(reg, line)] if m]
    return users

# returns the lines from the users file
def read_users(users_file):
    mesh_users_in = open(users_file, "r")
    lines = [line.rstrip('\n') for line in mesh_users_in]
    users = validate_users(lines)
    return users

def read_games(game_desc_file):
    try:
        f_games = open(game_desc_file, "r")
    except Exception as e:
        print("Game desc file failed to open")
        exit(2)

    reg = r'^\s*([\w\/\-.\_]+)\s+([\w\-.\_]+)\s+(\d+\.\d+|\d+)((?:\s+\w+)+)'

    games = []
    for line in f_games:
        m = re.match(reg, line)
        g_path = m.group(1)
        name = m.group(2)
        version = m.group(3)
        users = m.group(4).split()

        games.append([g_path, name, version, users])

    return games

def full_game_encrypt_test():
    pk_file = open('pk.out', 'wb')
    pk, sk = gen_keypair()
    pk_file.write(pk)
    pk_file.close()

    key_file = open('key.out', 'rb')
    key = key_file.read()
    key_file.close()
    nonce_file = open('nonce.out', 'rb')
    nonce = nonce_file.read()
    nonce_file.close()
    game_file = open('demo_files/2048', 'rb')
    game = game_file.read()
    encrypted_game = encrypt(key, nonce, game)
    # signed_encrypted = sign(encrypt_game, sk)

    out_file = open('nick.out', 'wb')
    out_file.write(encrypted_game)
    out_file.close()


def verify_everything(gamepath, pk, username, pin, salt, header_key, header_nonce, sk):
    # print("" + ''.join('\\x{:02x}'.format(x) for x in pk) + "")
    game_file = open(gamepath, 'rb')
    game = game_file.read()
    game_file.close()

    #s = sign(game, sk)

    # verify sig for entire file
    file_buf = verify_signature(game, pk)
    # split
    encrypted_header_len = unpack('Q', file_buf[:8])[0]
    # decrypt header
    #print("" + ''.join('\\x{:02x}'.format(x) for x in file_buf) + "")
    print(encrypted_header_len)
    encrypted_header = file_buf[8:(encrypted_header_len+8)]
    ciphertext = file_buf[encrypted_header_len+8:]
    header = decrypt(header_key, header_nonce, encrypted_header)
    #header = header.decode('utf-8')
    print(header)
    version = header[8:11]
    name = header[17:21]
    index = 22
    while index < len(header)- 10:
        for i in range(10):
            if(header[i+index] == 32):
                break
        allowed_user = header[index:index+i].decode()
        # 32 + 24 + 16 + 24
        i += 1
        encrypted_key_nonce = header[index+i:index+i+72]
        user_nonce = header[i+index+72:i+index+72+24]
        print(encrypted_key_nonce)
        print(user_nonce)

        index = i + index + 72 + 24
        if (allowed_user == username):
            print(username)
            user_key = gen_userkey(username, pin, salt, name.decode(), version.decode())
            game_key_nonce = decrypt(user_key, user_nonce, encrypted_key_nonce)
            game_key = game_key_nonce[:32]
            game_nonce = game_key_nonce[32:]
            decrypted_game = decrypt(game_key, game_nonce, ciphertext)
            file_name = name.decode() + version.decode() + username
            f = open(file_name, 'wb')
            f.write(decrypted_game)
            f.close()
            

    '''
    name = header_data[1][5:]
    user = header_data[2].split()
    user_name = user[0][6:]
    print(user_name)
    enc_game_key_nonce = base64.b64decode(user[1][1:])
    # print("Gamekeynonce: " + str(enc_game_key_nonce))
    user_nonce = base64.b64decode(user[2][1:])
    # print("user_nonce: " + str(user_nonce))
    userkey = gen_userkey(user_name, pin, salt, name, version)
    game_key_nonce = decrypt(userkey, user_nonce, enc_game_key_nonce)
    # print(game_key_nonce)
    game_key = game_key_nonce[:32]
    game_nonce = game_key_nonce[32:]
    # print(game_key)
    # print(game_nonce)
    # print(len(game_key))
    # print(len(game_nonce))
    decrypted_game = decrypt(game_key, game_nonce, ciphertext)
    f = open("out.out", 'wb')
    f.write(decrypted_game)
    f.close()
    '''
    print("Successful")

# Function is used to generate a key passed on user data
# Out file it then tested with the same outfile from C
def gen_userkey_test():
    salt_file = open('salt.out', 'rb')
    salt = salt_file.read()
    salt_file.close()
    userkey = gen_userkey("user1", "12345678", salt, "2048", "1.1")
    # Write to a file if nessary to verify
    #userkeyout_file = open('userkey.out', 'wb')
    #userkeyout_file.write(userkey)
    #userkeyout_file.close()

def new_full_game_decrypt_test():
    f = open("pk.out", "rb")
    pk = f.read()
    f.close()
    print(type(pk))
    print("" + ''.join('\\x{:02x}'.format(x) for x in pk) + "")
    f = open("demo_files/demo_games_test.txt", 'r')
    array = []
    for line in f:
        print(line)
        if(line != ''):
            game_path, name, version, users = load_game_txt(line)
            array.append([game_path, name, version, users])
    print(array)
    user_array, header_key, header_nonce, sk = load_factory_secrets()
    #print(user_array)
    sk = open("sk.out", 'rb').read()

    for game in array:
        print(game)
        for user in user_array:
            username = user[0]
            if username in game[3]:
                pin = user[1]
                salt = user[2]
                verify_everything(game[0], pk, username, pin, salt, header_key, header_nonce, sk)

def load_factory_secrets():
    f = open('files/generated/FactorySecrets.txt', 'r');
    lines = [line.rstrip('\n') for line in f]
    f.close()
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

def load_game_txt(line):
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
    users = m.group(4).split()
    # get list of games
    # get list of users
    # read ing stuff 
    return g_path, name, version, users



if __name__ == "__main__":
    #full_game_encrypt_test()
    #gen_userkey_test()
    new_full_game_decrypt_test()
    # pk_file = open('pk.out', 'wb')
    # pk, sk = gen_keypair()
    # pk_file.write(pk)
    # pk_file.close()

    # key_file = open('key.out', 'rb')
    # key = key_file.read()
    # key_file.close()
    # nonce_file = open('nonce.out', 'rb')
    # nonce = nonce_file.read()
    # nonce_file.close()
    # # read in data from files
    # # user pin salt
    # # game who_can_play_them

    # # for each game
    # #   generate game key
    # #       create header with meta data and encrypted game keys
    # #       encrypt header
    # #   encrypt game
    # #   append header+game
    # #   sign header+game
    # #   spit out signed file. 

    # users = read_users('demo_files/demo_users_salt.txt')
    # game_lines = read_games('demo_files/demo_games_test.txt')
    # for game in game_lines:
    #     encrypt_sign_file(users, game, sk, key, nonce, pk)

    # # read in arbitrary game file, pass in user, pin, salt, pk, key, nonce
    # game_file = open('2048-v1.0', 'rb')
    # pk_file = open('pk.out','rb')
    # nonce_file = open('nonce.out', 'rb')
    # key_file = open('key.out', 'rb')
    # game = game_file.read()
    # pk = pk_file.read()
    # nonce = nonce_file.read()
    # key = key_file.read()
    # user = "user1"
    # pin = "12345678"
    # salt = base64.b64decode(b'waUNqGdgxntpJBfyXFIO/w==')
    # game_file.close()
    # pk_file.close()
    # nonce_file.close()
    # key_file.close()

    # # verify the data

    # f = open('2048-v1.0', 'rb')
    # game = f.read()
    # f.close()
    # verify_everything(game, pk, pin, salt, key, nonce)
