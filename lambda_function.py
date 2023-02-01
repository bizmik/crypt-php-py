import base64
import binascii
import json

from Cryptodome import Random
from Cryptodome.Cipher import AES


# import sslcrypto,hashlib
def lambda_handler(event, context):
    # TODO implement

    # salt = 'any salt'

    # print(hex(int(salt, base=16)))

    salt = '34172bac9b7f5b85b770343bcf0dc61cddfebd52440338b7f81fde32dd0b7ca5'
    coded = my_encrypt("Hello", salt)

    print('CODED: ', coded)

    decoded = my_decrypt(coded, salt)
    print('DECODED: ', decoded)

    hardcoded = 'eyJpdiI6ImRHSmxIbUtHelFzdW1zZ2F2WGYzSEE9PSIsImRhdGEiOiJHczdrRzRvMFNtekxuUVU2OTVXTHV4ZUpVdG5NWFwvOTJsRkNPYzBzNVwva0k9In0='
    decoded = my_decrypt(hardcoded, salt)

    print('DECODED (hard): ', decoded)

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }


def my_encrypt(data, passphrase):
    """
         Encrypt using AES-256-CBC with random/shared iv
        'passphrase' must be in hex, generate with 'openssl rand -hex 32'
    """
    clean = 'n/a'
    try:
        key = binascii.unhexlify(passphrase)
        pad = lambda s: s + chr(16 - len(s) % 16) * (16 - len(s) % 16)
        iv = Random.get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_64 = base64.b64encode(cipher.encrypt(pad(data).encode('utf-8'))).decode('utf-8')
        iv_64 = base64.b64encode(iv).decode('utf-8')
        json_data = {'iv': iv_64, 'data': encrypted_64}
        clean = base64.b64encode(json.dumps(json_data).encode('utf-8')).decode('utf-8')
    except Exception as e:
        print("Cannot encrypt datas...")
        print(e)
        exit(1)
    return clean


def my_decrypt(data, passphrase):
    """
         Decrypt using AES-256-CBC with iv
        'passphrase' must be in hex, generate with 'openssl rand -hex 32'
        # https://stackoverflow.com/a/54166852/11061370
    """
    clean = 'n/a'
    try:
        unpad = lambda s: s[:-s[-1]]
        key = binascii.unhexlify(passphrase)
        encrypted = json.loads(base64.b64decode(data).decode('utf-8'))
        encrypted_data = base64.b64decode(encrypted['data'])
        iv = base64.b64decode(encrypted['iv'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        clean = unpad(decrypted).decode('utf-8').rstrip()
    except Exception as e:
        print("Cannot decrypt datas...")
        print(e)
        exit(1)
    return clean




lambda_handler(1, 1)
