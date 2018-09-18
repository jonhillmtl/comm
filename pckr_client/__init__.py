from .broadcaster import Broadcaster
from .frame import Frame

from Crypto.PublicKey import RSA 
from termcolor import colored

import argparse
import binascii
import json
import keyring
import os
import pprint
import requests
import socket
import uuid


argparser = argparse.ArgumentParser()
argparser.add_argument('command')
args, _ = argparser.parse_known_args()


def initiate_user():
    path = os.path.join("~/pckr/", args.number)
    path = os.path.expanduser(path)

    if os.path.exists(path):
        # TODO JHILL: ALSO CHECK SERVER
        print("already there")
    else:
        # TODO JHILL: tuck this away somewhere safe
        os.makedirs(path)
        new_key = RSA.generate(2048, e=65537) 
        public_key = new_key.publickey().exportKey("PEM") 
        private_key = new_key.exportKey("PEM") 

        public_path = os.path.join(path, "public.key")
        private_path = os.path.join(path, "private.key")

        with open(public_path, "wb") as f:
            f.write(public_key)

        with open(private_path, "wb") as f:
            f.write(private_key)

        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        response = requests.post('http://127.0.0.1:5000/user/initiate/', headers=headers, data=json.dumps(dict(
            phone_number=args.number,
            public_key=public_key.decode()
        )))
        token = response.json()['token']
        keyring.set_password("pckr", args.number, token)

        return True


def verify_user():
    token = keyring.get_password("pckr", args.number)

    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.post('http://127.0.0.1:5000/user/verify/', headers=headers, data=json.dumps(dict(
        phone_number=args.number,
        login_token=token
    )))
    print(response.json())


def broadcast_user():
    token = keyring.get_password("pckr", args.number)
    bc = Broadcaster(args.number, args.port)
    bc.start()
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.post('http://127.0.0.1:5000/user/broadcast/', headers=headers, data=json.dumps(dict(
        phone_number=args.number,
        login_token=token,
        ip=bc.serversocket.getsockname()[0],
        port=bc.port
    )))
    
    print(colored("broadcasting on {}:{}".format(bc.serversocket.getsockname()[0], bc.port), "green"))
    bc.join()


def ping_user():
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.get('http://127.0.0.1:5000/users/?number={}'.format(args.other_number), headers=headers)

    # oh boy tons of improvements required here
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((response.json()['users'][0]['ip'].strip(), response.json()['users'][0]['port']))

    frame = Frame(content=dict(), action="ping")
    sock.send(str(frame).encode())

    response = sock.recv(1024)
    pprint.pprint(json.loads(response.decode()), indent=4)


def send_file():
    if args.mime_type == "image/png":
        with open(args.filename, "rb") as f:
            content = f.read()
    else:
        with open(args.filename, "r") as f:
            content = f.read()

    mime_type = args.mime_type

    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.get('http://127.0.0.1:5000/users/?number={}'.format(args.other_number), headers=headers).json()

    encryption_key = str(uuid.uuid4())
    message_id = str(uuid.uuid4())
    public_key_text = response['users'][0]['public_key']

    key_frame = Frame(
        action='send_file_transmit_key',
        content=dict(encryption_key=encryption_key),
        mime_type='application/json',
        encryption_type='public_key',
        encryption_key=public_key_text,
        message_id=message_id
    )
    # print(key_frame)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((response['users'][0]['ip'].strip(), response['users'][0]['port']))

    sock.send(str(key_frame).encode())
    key_response = sock.recv(4096)
    # print(key_response)

    frames = Frame.make_frames(
        content,
        "send_file",
        encryption_type='symmetric_key',
        encryption_key=encryption_key,
        mime_type=mime_type,
        message_id=message_id
    )

    for frame in frames:
        # TODO JHILL: tuck this away somewhere with more error checking
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((response['users'][0]['ip'].strip(), response['users'][0]['port']))
        print(len(str(frame).encode()))
        sock.send(str(frame).encode())
        frame_response = sock.recv(4096)
        # print(frame_response)


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
    else:
        print("no")
    
    