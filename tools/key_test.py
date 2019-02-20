from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import re
import pickle

#import nacl.utils
#import nacl.secret
from struct import *
import pysodium
import array
import base64


def write_factory_secrets(f, h):
    """Write any factory secrets. The reference implementation has none
    TODO: Evaluate the size of the keys
    f: open file to write the factory secrets to
    """
    # key = RSA.generate(4096)
    # f.write(key.exportKey())
    # h.write(key.publicKey.exportKey())
    encrypt_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048, 
        backend=default_backend()
        )
    encrypt_key_priv = encrypt_key.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.NoEncryption()
        )

    public_key = encrypt_key.public_key()
    encrypt_key_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    f.write(encrypt_key_pub.decode('utf-8'))
    f.write("*****\n")
    shared_key = os.urandom(64)
    f.write(base64.b64encode(shared_key).decode('utf-8'))

    s = """
/*
* This is an automatically generated file by provisionSystem.py
*
*
*/

#ifndef __SECRET_H__
#define __SECRET_H__

static char* encrypt_priv_key = \""""
    s += base64.b64encode(encrypt_key_priv).decode('utf-8')
    s +="""\";
static char* shared_key = \""""
    s += base64.b64encode(shared_key).decode('utf-8')
    s += """\" ;

#endif /* __SECRET_H__ */
"""
    h.write(s)

def open_users(path):
    f_mesh_users_in = open(path, "r")
    lines = [line.rstrip('\n') for line in f_mesh_users_in]
    users = validate_users(lines)
    return users

def validate_users(lines):
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

def create_factory_secrets(users, f, h):
    """Write any factory secrets. The reference implementation has none
    f: open file to write the factory secrets to
    h: open file to write data to pass along to shell
    """
    for user in users:
        f.write(user[0] + ' ' + user[1] + ' salt\n')
    # f.write("This is totes a key again\n")

    sign_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )
    sign_key_priv = sign_key.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.NoEncryption()
        )
    public_key = sign_key.public_key()
    sign_key_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    f.write(base64.b64encode(sign_key_priv).decode('utf-8'))

    s = """
/*
* This is an automatically generated file by provisionSystem.py
*
*
*/

#ifndef __SECRET_H__
#define __SECRET_H__

static char* sign_public_key = \""""
    s += base64.b64encode(sign_key_pub).decode('utf-8')
    s += """\" ;

#endif /* __SECRET_H__ */
"""
    h.write(s)

def read_factory_secrets(f):
    lines = [line.rstrip('\n') for line in f]
    key = lines[-1:]
    # print(key)
    # print(lines[:-1])
    # users = validate_users(lines[:-1])
    array = []
    for user in lines:
        array.append(user.split(' '))
    # print(array)
    return array, key

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

def gen_userkey(user, pin, salt, game_name, version):
    password = str(user) + str(pin) + str(game_name) + str(version)
    #salt = os.urandom(pysodium.crypto_pwhash_SALTBYTES)
    key = pysodium.crypto_pwhash(32, password, salt, pysodium.crypto_pwhash_OPSLIMIT_MIN, pysodium.crypto_pwhash_MEMLIMIT_MIN, 2)
    #print(key)
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
            print(user_data)
            username = user_data[0]
            user_pin = user_data[1]
            user_salt = base64.b64decode(user_data[2])
            print(user_salt)
            user_key = gen_userkey(username, user_pin, user_salt, name, version)
            encrypted_gamekey, nonce = encrypt_game_key(user_key, gamekey, gamenonce)
            b64_encoded_gamekey = base64.b64encode(encrypted_gamekey)
            b64_encoded_nonce = base64.b64encode(nonce)
            header += bytes("users:%s %s %s\n" % (user, b64_encoded_gamekey, b64_encoded_nonce), "utf-8")
    #print("Header")
    #print(header)
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
    gamebin = open(gamepath, 'rb').read();
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
    header_game = str(encrypted_header) + str(encrypted_game)
    signed_file = sign(header_game, sk)
    print(len(sk))
    header_game = verify_signature(signed_file, pk)
    fp = open(out_name,'wb');
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

if __name__ == "__main__":
    # f = open("factorySecrets.txt", "w")
    # h = open("secret.h", "w")
    # # write_factory_secrets(f, h)
    # users = open_users('demo_files/demo_users.txt')
    # create_factory_secrets(users, f, h)
    # f.close()
    # f = open("factorySecrets.txt", "r")
    # array, key = read_factory_secrets(f)
    # reate_games(f)
    # f.close()

    # read in data from files
    # user pin salt
    # game who_can_play_them

    # for each game
    #   generate game key
    #       create header with meta data and encrypted game keys
    #       encrypt header
    #   encrypt game
    #   append header+game
    #   sign header+game
    #   spit out signed file. 
    pk_file = open('pk.out', 'wb')
    pk, sk = gen_keypair()
    print(len(pk))
    print(len(sk))
    print(pysodium.crypto_sign_PUBLICKEYBYTES)
    pk_file.write(pk)
    pk_file.close()

    key_file = open('key.out', 'rb')
    key = key_file.read()
    key_file.close()
    nonce_file = open('nonce.out', 'rb')
    nonce = nonce_file.read()
    nonce_file.close()

    users = read_users('demo_files/demo_users_salt.txt')
    game_lines = read_games('demo_files/demo_games_test.txt')
    for game in game_lines:
        encrypt_sign_file(users, game, sk, key, nonce, pk)

    # read in arbitrary game file, pass in user, pin, salt, pk, key, nonce
    game_file = open('2048-v1.0', 'rb')
    pk_file = open('pk.out','rb')
    nonce_file = open('nonce.out', 'rb')
    key_file = open('key.out', 'rb')
    game = game_file.read()
    pk = pk_file.read()
    nonce = nonce_file.read()
    key = key_file.read()
    user = "user1"
    pin = "12345678"
    salt = base64.b64encode(b'waUNqGdgxntpJBfyXFIO/w==')
    game_file.close()
    pk_file.close()
    nonce_file.close()
    key_file.close()
    # unsign
    # get len
    # split header and game
    # decrypt header
    # parse to get userkey
    # decrypt gamekeynonce
    # decrypt game
    # write game
    '''
    salt, user_key = gen_userkey("user1", "12345678", "2048", "1.1")
    salt_file = open("salt.out", 'wb')
    salt_file.write(salt)
    salt_file.close()


    f = open('demo_files/2048', 'rb')
    message = f.read()
    #message = b"The president will be exiting through the lower levels."
    ciphertext, game_key, game_nonce = generate_and_encrypt(message)
    # given the user key, encrypt the game_key and nonce
    encoded_gamekey_nonce, user_nonce  = encrypt_game_key(user_key, game_key, game_nonce)
    user_nonce_file.write(user_nonce)
    # pack data as 64 bits
    encrypted_header_len = pack('Q', len(encoded_gamekey_nonce))
    print(encrypted_header_len)

    file_buf = encrypted_header_len + encoded_gamekey_nonce + ciphertext

    signed_encrypted, pk = sign_game(file_buf, pk_file)
    # this is everything
    out_file.write(signed_encrypted)
    '''
    # verify sig for entire file
    file_buf = verify_signature(pk, game)
    # split
    encrypted_header_len = unpack('Q', file_buf[:8])[0]
    # decrypt header

    encrypted_header = file_buf[8:(encrypted_header_len+8)]
    ciphertext = file_buf[encrypted_header_len+8:]
    header = decrypt(key, nonce, encrypted_header)
    print(header)
    '''
    derived_gamekey_nonce = decrypt(user_key, user_nonce, encoded_gamekey_nonce)
    #print(derived_gamekey_nonce)
    derived_gamekey = derived_gamekey_nonce[:32]
    derived_nonce = derived_gamekey_nonce[32:]

    message = decrypt(derived_gamekey, derived_nonce, ciphertext)

    print(message)

    user_nonce_file.close()
    out_file.close()
    pk_file.close()
    #print(cipherText[:16])
    #use_key(key, nonce, cipherText)
    '''
