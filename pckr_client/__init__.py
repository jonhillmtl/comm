from .broadcaster import Broadcaster
from .frame import Frame

from Crypto.PublicKey import RSA 
from termcolor import colored
from Crypto.Cipher import Blowfish
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5

import argparse
import binascii
import json
import keyring
import os
import pprint
import requests
import socket
import uuid
from .utilities import get_user_ip_port, send_frame, post_json_request, get_user_path


argparser = argparse.ArgumentParser()
argparser.add_argument('command')
args, _ = argparser.parse_known_args()

# TODO JHILL: put into utilities file
BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS),encoding='utf8')


def initiate_user():
    user_path = get_user_path(args.number)

    if os.path.exists(user_path):
        # TODO JHILL: ALSO CHECK SERVER
        print("already there")
    else:
        # TODO JHILL: tuck this away somewhere safe
        os.makedirs(user_path)

        new_key = RSA.generate(2048, e=65537) 
        public_key = new_key.publickey().exportKey("PEM") 
        private_key = new_key.exportKey("PEM") 

        public_path = os.path.join(user_path, "public.key")
        private_path = os.path.join(user_path, "private.key")

        with open(public_path, "wb") as f:
            f.write(public_key)

        with open(private_path, "wb") as f:
            f.write(private_key)

        response = post_json_request('http://127.0.0.1:5000/user/initiate/', dict(
            phone_number=args.number,
            public_key=public_key.decode()
        ))
        token = response['token']
        keyring.set_password("pckr", args.number, token)

        return True


def request_public_key():
    public_key_path = os.path.expanduser(os.path.join("~/pckr/", args.number, "public.key"))
    public_key_text = open(public_key_path).read()

    frame = Frame(
        content=dict(
            number=args.number,
            public_key=public_key_text
        ), 
        action="request_public_key"
    )

    (ip, port) = get_user_ip_port(args.other_number)
    response = send_frame(frame, ip, port)
    pprint.pprint(response, indent=4)


def verify_user():
    token = keyring.get_password("pckr", args.number)

    response = post_json_request('http://127.0.0.1:5000/user/verify/', data=dict(
        phone_number=args.number,
        login_token=token
    ))
    print(response)


def broadcast_user():
    token = keyring.get_password("pckr", args.number)
    bc = Broadcaster(args.number, args.port)
    bc.start()

    response = post_json_request('http://127.0.0.1:5000/user/broadcast/', dict(
        phone_number=args.number,
        login_token=token,
        ip=bc.serversocket.getsockname()[0],
        port=bc.port
    ))

    print(colored("registered with coordination server: {}".format(response), "yellow"))
    print(colored("broadcasting on {}:{}".format(bc.serversocket.getsockname()[0], bc.port), "green"))
    bc.join()


def ping_user():
    (ip, port) = get_user_ip_port(args.other_number)
    frame = Frame(content=dict(), action="ping")
    response = send_frame(frame, ip, port)
    pprint.pprint(response, indent=4)


def send_file():
    if args.mime_type == "image/png":
        with open(args.filename, "rb") as f:
            content = f.read()
    else:
        with open(args.filename, "r") as f:
            content = f.read()

    mime_type = args.mime_type

    (ip, port) = get_user_ip_port(args.other_number)

    encryption_key = str(uuid.uuid4())
    message_id = str(uuid.uuid4())

    key_frame = Frame(
        action='send_file_transmit_key',
        content=dict(encryption_key=encryption_key),
        mime_type='application/json',
        encryption_type='public_key',

        # TODO JHILL: well this is mega broken now!
        encryption_key='',
        message_id=message_id
    )
    send_frame(key_frame, ip, port)

    frames = Frame.make_frames(
        content,
        "send_file",
        encryption_type='symmetric_key',
        encryption_key=encryption_key,
        mime_type=mime_type,
        message_id=message_id
    )

    for frame in frames:
        send_frame(frame, ip, port)


def process_public_key_responses():
    responses_path = os.path.expanduser(os.path.join("~/pckr/", args.number, "public_key_responses"))
    for d, sds, files in os.walk(responses_path):
        for f in files:
            if f[-5:] == '.json':
                request_path = os.path.join(d, f)
                with open(request_path) as f:
                    data = json.loads(f.read())

                    public_keys_path = os.path.expanduser(os.path.join("~/pckr/", args.number, "public_keys", data['number']))
                    if not os.path.exists(public_keys_path):
                        os.makedirs(public_keys_path)
    
                    public_key_path = os.path.join(public_keys_path, 'public.key')
                    with open(public_key_path, "w+") as pkf:
                        private_key_path = os.path.expanduser(os.path.join("~/pckr/", args.number, "private.key"))
                        private_key_text = open(private_key_path).read()
                        rsakey = RSA.importKey(private_key_text)
                        rsakey = PKCS1_OAEP.new(rsakey)

                        public_key_password = rsakey.decrypt(binascii.unhexlify(data['password']))
                        
                        # TODO JHILL: don't store the password inside json for fuck's sake,
                        # just put it as the value
                        public_key_password = json.loads(public_key_password)['password'].encode()
                        c1  = Blowfish.new(public_key_password, Blowfish.MODE_ECB)
                        decrypted_text = c1.decrypt(binascii.unhexlify(data['public_key']))
                        
                        # TODO JHILL: this needs to be depadded
                        print(decrypted_text)
                        pkf.write(decrypted_text.decode())


def process_public_key_requests():
    requests_path = os.path.expanduser(os.path.join("~/pckr/", args.number, "public_key_requests"))
    for d, sds, files in os.walk(requests_path):
        for f in files:
            if f[-5:] == '.json':
                request_path = os.path.join(d, f)
                with open(request_path) as f:
                    data = json.loads(f.read())

                    print("public key request from: data['number']")
                    choice = input("send it to them? [y/n]")

                    if choice == 'y':
                        # TODO JHILL: make this actually unique
                        password = 'abcdefghijkl'
                        cipher = Blowfish.new(password.encode(), Blowfish.MODE_ECB)

                        public_key_path = os.path.expanduser(os.path.join("~/pckr/", args.number, "public.key"))
                        public_key_text = open(public_key_path).read()
                        public_key_encrypted = cipher.encrypt(pad(public_key_text))
                        public_key_encrypted = binascii.hexlify(public_key_encrypted).decode()

                        rsa_key = RSA.importKey(data['public_key'])
                        rsa_key = PKCS1_OAEP.new(rsa_key)
                        payload = dict(
                            password=password
                        )

                        password_rsaed = rsa_key.encrypt(json.dumps(payload).encode())
                        password_rsaed = binascii.hexlify(password_rsaed).decode()

                        frame = Frame(
                            action='send_public_key',
                            content=dict(
                                public_key=public_key_encrypted,
                                number=args.number,
                                password=password_rsaed
                            ),
                            mime_type='application/json'
                        )

                        (ip, port) = get_user_ip_port(data['number'])
                        frame_response = send_frame(frame, ip, port)
                        pprint.pprint(frame_response)

                        # TODO JHILL: delete the file if it's all good?

def main():
    global args
    if args.command == 'initiate_user':
        argparser.add_argument("--number", required=True)
        args = argparser.parse_args()
        initiate_user()

    elif args.command == 'broadcast_user':
        argparser.add_argument("--number", required=True)
        argparser.add_argument("--port", type=int, required=True)
        args = argparser.parse_args()
        broadcast_user()

    elif args.command == 'verify_user':
        argparser.add_argument("--number", required=True)
        args = argparser.parse_args()
        verify_user()

    elif args.command == 'ping_user':
        argparser.add_argument("--number", required=True)
        argparser.add_argument("--other_number", required=True)

        args = argparser.parse_args()
        ping_user()

    elif args.command == 'send_file':
        argparser.add_argument("--number", required=True)
        argparser.add_argument("--other_number", required=True)
        argparser.add_argument("--filename", required=True)
        argparser.add_argument("--mime_type", required=True)

        args = argparser.parse_args()
        send_file()

    elif args.command == 'request_public_key':
        argparser.add_argument("--number", required=True)
        argparser.add_argument("--other_number", required=True)

        args = argparser.parse_args()
        request_public_key()

    elif args.command == 'process_public_key_requests':
        argparser.add_argument("--number", required=True)
        args = argparser.parse_args()
        process_public_key_requests()

    elif args.command == 'process_public_key_responses':
        argparser.add_argument("--number", required=True)
        args = argparser.parse_args()
        process_public_key_responses()

    else:
        print("no")
    
    