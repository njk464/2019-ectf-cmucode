from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

f = open("myfile", "rb")


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