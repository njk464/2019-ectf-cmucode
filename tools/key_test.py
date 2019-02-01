from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import binascii

def main():


    with open("private.pem", "rb") as private_key_file:
        string = private_key_file.read()
        result = string.split("*****\n")
        # print(result[0])
        # print("Next:")
        # print(result[1])
        private_key = serialization.load_pem_private_key(
            result[0],
            password = None,
            backend=default_backend()
        )
        message = b"A message I want to sign"
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(signature)
        # message=b"A message I want to sign"

        # string = private_key_file.read()
        # result = string.split("*****\n")
        # print(result[0])
        # print("Next:")
        # print(result[1])

    # with open("public.pem", "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            result[1],
            backend=default_backend()
        )
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

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
    public_key = encrypt_key.public_key()
    sign_key_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    f.write(sign_key_priv.decode('utf-8'))

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
static char* sign_public_key = \""""
    s += base64.b64encode(sign_key_priv).decode('utf-8')
    s += """\" ;

#endif /* __SECRET_H__ */
"""
    h.write(s)

if __name__ == "__main__":
    f = open("factorySecrets.txt", "w")
    h = open("secret.h", "w")
    write_factory_secrets(f, h)