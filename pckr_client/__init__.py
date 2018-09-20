from .broadcaster import Broadcaster
from .frame import Frame
from .user import User
from .utilities import send_frame, post_json_request, encrypt_symmetric, hexstr2bytes

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


def challenge_user():
    user = User(args.username)
    challenge_text = str(uuid.uuid4())

    frame = Frame(
        content=dict(
            from_username=args.username,
            challenge_text=challenge_text
        ),
        action="challenge_user"
    )

    response = send_frame(frame, args.u2)

    # TODO JHILL: check return for success or not...
    # don't just charge through it
    encrypted_challenge = binascii.unhexlify(response['encrypted_challenge'])
    decrypted_challenge = user.rsakey.decrypt(encrypted_challenge).decode()
    print(colored(challenge_text, "blue"))
    print(colored(decrypted_challenge, "blue"))

    if challenge_text == decrypted_challenge:
        print(colored("good", "green"))
    else:
        print(colored("bad", "red"))


def request_public_key():
    user = User(args.username)

    frame = Frame(
        content=dict(
            from_username=args.username,
            public_key=user.public_key_text
        ), 
        action="request_public_key"
    )

    response = send_frame(frame, args.u2)
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
    frame = Frame(content=dict(), action="ping")
    response = send_frame(frame, args.u2)
    pprint.pprint(response, indent=4)


def send_message():
    # TODO JHILL: Put this into a transfer object
    if args.mime_type == "image/png":
        with open(args.filename, "rb") as f:
            content = f.read()
    else:
        with open(args.filename, "r") as f:
            content = f.read()

    mime_type = args.mime_type

    encryption_key = str(uuid.uuid4())
    message_id = str(uuid.uuid4())

    user = User(args.username)
    public_key_text = user.get_contact_public_key(args.u2)
    key_frame = Frame(
        action='send_message_key',
        content=dict(encryption_key=encryption_key),
        mime_type='application/json',
        encryption_type='public_key',
        encryption_key=public_key_text,
        message_id=message_id
    )
    send_frame(key_frame, args.u2)

    frames = Frame.make_frames(
        content,
        "send_message",
        encryption_type='symmetric_key',
        encryption_key=encryption_key,
        mime_type=mime_type,
        message_id=message_id
    )

    for frame in frames:
        send_frame(frame, args.u2)


def process_public_key_responses():
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
            # TODO JHILL: use bin2hexstr
            public_key_encrypted = binascii.hexlify(public_key_encrypted).decode()

            # TODO JHILL: put in utilities file now
            rsa_key = RSA.importKey(request['public_key'])
            rsa_key = PKCS1_OAEP.new(rsa_key)

            password_rsaed = rsa_key.encrypt(password)

            # TODO JHILL: use bin2hexstr
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

            frame_response = send_frame(frame, request['from_username'])
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

    elif args.command == 'send_message':
        argparser.add_argument("--username", required=False)
        argparser.add_argument("--u2", required=True)
        argparser.add_argument("--filename", required=True)
        argparser.add_argument("--mime_type", required=False, default='image/png')
        massage_args()

        send_message()
    
    elif args.command == 'challenge_user':
        argparser.add_argument("--username", required=False)
        argparser.add_argument("--u2", required=True)
        massage_args()

        challenge_user()

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
    
    