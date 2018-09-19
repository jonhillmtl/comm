from .broadcaster import Broadcaster
from .frame import Frame
from .user import User
from .utilities import get_user_ip_port, send_frame, post_json_request, encrypt_symmetric

from Crypto.PublicKey import RSA 
from termcolor import colored
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
import sys



argparser = argparse.ArgumentParser()
argparser.add_argument('command')
args, _ = argparser.parse_known_args()

# TODO JHILL: put into utilities file
BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS),encoding='utf8')


def initiate_user():
    user = User(args.username)

    if user.exists:
        # TODO JHILL: ALSO CHECK SERVER
        print("already there")
    else:
        user.initiate_directory_structure()
        user.initiate_rsa()

        response = post_json_request('http://127.0.0.1:5000/user/initiate/', dict(
            username=user.username
        ))
        token = response['token']
        keyring.set_password("pckr", args.username, token)

        return True


def request_public_key():
    user = User(args.username)

    frame = Frame(
        content=dict(
            from_username=args.username,
            public_key=user.public_key_text
        ), 
        action="request_public_key"
    )

    (ip, port) = get_user_ip_port(args.u2)
    response = send_frame(frame, ip, port)
    pprint.pprint(response, indent=4)


def verify_user():
    token = keyring.get_password("pckr", args.username)

    response = post_json_request('http://127.0.0.1:5000/user/verify/', data=dict(
        username=args.username,
        login_token=token
    ))
    print(response)


def broadcast_user():
    # TODO JHILL: verify the user exists, both here and on the server!
    token = keyring.get_password("pckr", args.username)
    bc = Broadcaster(args.username, args.port)
    bc.start()

    response = post_json_request('http://127.0.0.1:5000/user/broadcast/', dict(
        username=args.username,
        login_token=token,
        ip=bc.serversocket.getsockname()[0],
        port=bc.port
    ))

    print(colored("registered with coordination server: {}".format(response), "yellow"))
    print(colored("broadcasting on {}:{}".format(bc.serversocket.getsockname()[0], bc.port), "green"))
    bc.join()


def ping_user():
    (ip, port) = get_user_ip_port(args.u2)
    frame = Frame(content=dict(), action="ping")
    response = send_frame(frame, ip, port)
    pprint.pprint(response, indent=4)


def send_file():
    # TODO JHILL: Put this into a transfer object
    if args.mime_type == "image/png":
        with open(args.filename, "rb") as f:
            content = f.read()
    else:
        with open(args.filename, "r") as f:
            content = f.read()

    mime_type = args.mime_type

    (ip, port) = get_user_ip_port(args.u2)

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
    # TODO JHILL: needs to be tested!
    user = User(args.username)
    for response in user.public_key_responses:
        user.process_public_key_response(response)

def process_public_key_requests():
    user = User(args.username)
    print(user.public_key_requests)
    for request in user.public_key_requests:
        print(request)
        print("request_public_key message from: {}".format(request['from_username']))
        choice = input("send it to them? [y/n]")

        # TODO JHILL: none of this should be here
        if choice == 'y':
            # TODO JHILL: make this actually unique
            password = b'abcdefghijkl'

            # TODO JHILL: this is available on the user object now
            public_key_path = os.path.expanduser(os.path.join("~/pckr/", args.username, "public.key"))
            public_key_text = open(public_key_path).read()

            public_key_encrypted = encrypt_symmetric(public_key_text, password)
            public_key_encrypted = binascii.hexlify(public_key_encrypted).decode()

            rsa_key = RSA.importKey(request['public_key'])
            rsa_key = PKCS1_OAEP.new(rsa_key)

            password_rsaed = rsa_key.encrypt(password)
            password_rsaed = binascii.hexlify(password_rsaed).decode()

            frame = Frame(
                action='public_key_response',
                content=dict(
                    public_key=public_key_encrypted,
                    from_username=args.username,
                    password=password_rsaed
                ),
                mime_type='application/json'
            )

            (ip, port) = get_user_ip_port(request['from_username'])
            frame_response = send_frame(frame, ip, port)
            pprint.pprint(frame_response)

            # TODO JHILL: delete the file if it's all good?

def massage_args():
    global args

    args = argparser.parse_args()
    if args.username is None:
        username = os.getenv('PCKR_USERNAME', None)
        if username:
            print(colored("used ENV to get username: {}".format(username), "yellow"))
            sys.argv.extend(['--username', username])
        else:
            print(colored("no username found on command line or in ENV", "red"))
            sys.exit(1)
    
    # then reparse them to grab any --username that might have been added
    args = argparser.parse_args()
    print(args.username)


def main():
    # TODO JHILL: this file could be a lot smaller
    # TODO JHILL: read the username from the environment if it's not present?
    global args
    if args.command == 'initiate_user':
        argparser.add_argument("--username", required=False)
        massage_args()

        initiate_user()

    elif args.command == 'broadcast_user':
        argparser.add_argument("--username", required=False, default=None)
        argparser.add_argument("--port", type=int, required=False, default=8050)
        massage_args()

        broadcast_user()

    elif args.command == 'verify_user':
        argparser.add_argument("--username", required=True)
        massage_args()

        verify_user()

    elif args.command == 'ping_user':
        argparser.add_argument("--username", required=False)
        argparser.add_argument("--u2", required=True)
        massage_args()

        ping_user()

    elif args.command == 'send_file':
        argparser.add_argument("--username", required=False)
        argparser.add_argument("--u2", required=True)
        argparser.add_argument("--filename", required=True)
        argparser.add_argument("--mime_type", required=False, default='image/png')
        massage_args()

        send_file()

    elif args.command == 'request_public_key':
        argparser.add_argument("--username", required=False)
        argparser.add_argument("--u2", required=True)
        massage_args()

        request_public_key()

    elif args.command == 'process_public_key_requests':
        argparser.add_argument("--username", required=False)
        massage_args()

        process_public_key_requests()

    elif args.command == 'process_public_key_responses':
        argparser.add_argument("--username", required=False)
        massage_args()

        process_public_key_responses()

    else:
        print(colored("unrecognized command", "red"))
    
    