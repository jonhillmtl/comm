import requests
import socket
import json
import os
import blowfish
import binascii
import hashlib
from termcolor import colored

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA 

def command_header(action, args):
    return colored("{}\n*\n* {}\n*\n{}\n*\n{}\n\n".format(
        "*" * 100,
        action,
        "\n".join(["* {}: {}".format(k, v) for k, v in vars(args).items()]),
        "*" * 100
    ), "blue")


def split_contents(contents, split_size=4096*2):
    splits = []
    index = 0
    while index < len(contents):
         splits.append(contents[index:index+split_size])
         index = index + split_size
    return splits


def hexstr2bytes(hs):
    assert type(hs) == str
    return binascii.unhexlify(hs)


def bytes2hexstr(bs):
    assert type(bs) == bytes
    return binascii.hexlify(bs).decode()


def str2hashed_hexstr(s):
    if type(s) == str:
        s = s.encode()

    m = hashlib.sha256()
    m.update(s)
    return bytes2hexstr(m.digest())


def pad_content(content):
    padder = ' '
    if type(content) == bytes:
        padder = b' '
    content = content + (padder * (16 - (len(content) % 16)))
    return content


def generate_rsa_pub_priv():
    return RSA.generate(2048, e=65537) 


def encrypt_rsa(content, public_key_text):
    if type(content) == str:
        content = content.encode()

    return PKCS1_OAEP.new(RSA.importKey(public_key_text)).encrypt(content)

def decrypt_rsa(content, private_key_text):
    if type(content) == str:
        content = content.encode()

    return PKCS1_OAEP.new(RSA.importKey(private_key_text)).decrypt(content)

def encrypt_symmetric(content, password):
    if type(password) is not bytes:
        password = password.encode()

    content = pad_content(content)
    if type(content) is not bytes:
        content = content.encode()

    cipher = blowfish.Cipher(password)
    data_encrypted = b"".join(cipher.encrypt_ecb(content))
    data_decrypted = b"".join(cipher.decrypt_ecb(data_encrypted))
    assert content == data_decrypted

    return data_encrypted


def decrypt_symmetric(content, password):
    if type(password) is not bytes:
        password = password.encode()

    if type(content) is not bytes:
        content = content.encode()

    cipher = blowfish.Cipher(password)
    data_decrypted = b"".join(cipher.decrypt_ecb(content))

    return data_decrypted.decode().strip()


def normalize_path(path):
    return os.path.normpath(os.path.abspath(os.path.expanduser(path)))


def send_frame_users(frame, u1, u2):
    ip, port = u1.get_contact_ip_port(u2)
    if ip and port:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.connect((ip.strip(), int(port)))
            frame_str = str(frame).encode()
            len_sent = sock.send(frame_str)
            assert len_sent == len(frame_str)
            response = json.loads(sock.recv(4096).decode())
            sock.close()
            return response
        except ConnectionRefusedError:
            return dict(success=False, error="connection refused")
    else:
        # TODO JHILL: remove them from the cache
        # and then send out a seek user for them
        return dict(success=False, error='ip:port unknown')