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

import nacl.utils
import nacl.secret

import pysodium
import array

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

def generate_keys(out_file):
    # This must be kept secret, this is the combination to your safe
    #key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    key = pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
    #print(len(key))
    # This is your safe, you can use it to encrypt or decrypt messages
    #box = nacl.secret.SecretBox(key)

    # This is our message to send, it must be a bytestring as SecretBox will
    #   treat it as just a binary blob of data.
    # message = b"The president will be exiting through the lower levels."
    f = open('demo_files/2048', 'rb')
    message = f.read()
    print(len(message))
    # This is a nonce, it *MUST* only be used once, but it is not considered
    #   secret and can be transmitted or stored alongside the ciphertext. A
    #   good source of nonces are just sequences of 24 random bytes.
    #nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    #print(len(nonce))
    #encrypted = box.encrypt(message, nonce)
    cipherText = pysodium.crypto_secretbox(message, nonce, key)
    (message, nonce, key)
    #print(len(cipherText))
    out_file.write(cipherText)

    return key, nonce

def use_key(key, nonce, cipherText):

    #box = nacl.secret.SecretBox(key)
    #cipherText = file.read()
    #plaintext = box.decrypt(encrypted, nonce)
    #print("cipherText: 0x"+",0x".join("{:02x}".format(ord(c)) for c in cipherText))
    #print("nonce: 0x"+",0x".join("{:02x}".format(ord(c)) for c in nonce))
    #print("key: 0x"+",0x".join("{:02x}".format(ord(c)) for c in key))
    plaintext = pysodium.crypto_secretbox_open(cipherText, nonce, key)
    # print("The message is: " + str(plaintext))

if __name__ == "__main__":
    # f = open("factorySecrets.txt", "w")
    # h = open("secret.h", "w")
    # # write_factory_secrets(f, h)
    # users = open_users('demo_files/demo_users.txt')
    # create_factory_secrets(users, f, h)
    # f.close()
    # f = open("factorySecrets.txt", "r")
    # array, key = read_factory_secrets(f)
    # # create_games(f)
    # f.close()
    out_file = open('game.out', 'wb')
    key_file = open('key.out', 'wb')
    nonce_file = open('nonce.out', 'wb')
    key, nonce = generate_keys(out_file)
    key_file.write(key)
    nonce_file.write(nonce)
    out_file.close()
    key_file.close()
    nonce_file.close()
    cipherText = open('game.out', 'rb').read()
    key = open('key.out', 'rb').read()
    nonce = open('nonce.out', 'rb').read()
    use_key(key, nonce, cipherText)
