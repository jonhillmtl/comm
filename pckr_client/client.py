from .broadcaster import Broadcaster
from .frame import Frame
from .user import User
from .utilities import send_frame, post_json_request, encrypt_symmetric, hexstr2bytes, bytes2hexstr, get_user_ip_port

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


def init_user():
    user = User(args.username)

    if user.exists:
        # TODO JHILL: ALSO CHECK SERVER
        print(colored("this user already exists: {}".format(args.username), "red"))
    else:
        user.initiate_directory_structure()
        user.initiate_rsa()

        response = post_json_request('http://127.0.0.1:5000/user/initiate/', dict(
            username=user.username
        ))
        token = response['token']
        keyring.set_password("pckr", args.username, token)

        print(colored("created user: {}".format(args.username), "green"))

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
    encrypted_challenge = hexstr2bytes(response['encrypted_challenge'])
    decrypted_challenge = user.private_rsakey.decrypt(encrypted_challenge).decode()
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
    import time
    t = time.time()
    # TODO JHILL: ping the user first...
    # and if it doesn't work take them out of the IP cache
    user = User(args.username)
    public_key_text = user.get_contact_public_key(args.u2)
    if public_key_text is None:
        print(colored("public_key for {} not found, can't send message".format(args.u2), "red"))
        sys.exit(1)

    # TODO JHILL: Put this into a transfer object
    if args.mime_type == "image/png":
        with open(args.filename, "rb") as f:
            content = f.read()
    else:
        with open(args.filename, "r") as f:
            content = f.read()

    encryption_key = str(uuid.uuid4())
    message_id = str(uuid.uuid4())

    rsa_key = RSA.importKey(public_key_text)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    payload_content = rsa_key.encrypt(encryption_key.encode())
    payload_content = bytes2hexstr(payload_content)

    (ip, port) = get_user_ip_port(args.u2)
    key_frame = Frame(
        action='send_message_key',
        message_id=message_id,
        content=payload_content
    )
    send_frame(key_frame, ip=ip, port=port)

    ft = time.time()
    encrypted_content = encrypt_symmetric(
        content,
        encryption_key.encode()
    )

    frames = Frame.make_frames(
        bytes2hexstr(encrypted_content),
        "send_message",
        mime_type=args.mime_type,
        message_id=message_id
    )
    print(time.time() -ft)

    for frame in frames:
        send_frame(frame, ip=ip, port=port)

    print("sent {} megabytes in {} seconds".format(len(content) / 1024 * 1024, time.time() - t))


def process_public_key_responses():
    user = User(args.username)
    for response in user.public_key_responses:
        user.process_public_key_response(response)


def process_public_key_requests():
    user = User(args.username)
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
            public_key_encrypted = bytes2hexstr(public_key_encrypted)

            # TODO JHILL: put in utilities file now
            rsa_key = RSA.importKey(request['public_key'])
            rsa_key = PKCS1_OAEP.new(rsa_key)

            password_rsaed = rsa_key.encrypt(password)
            password_rsaed = bytes2hexstr(password_rsaed)

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


COMMANDS = [
    'init_user',
    'broadcast_user',
    'verify_user',
    'ping_user',
    'send_message',
    'challenge_user',
    'request_public_key',
    'process_public_key_requests',
    'process_public_key_responses'
]


COMMAND_ALIASES = dict(
    iu='init_user',
    bu='broadcast_user',
    vu='verify_user',
    pu='ping_user',
    sm='send_message',
    cu='challenge_user',
    rpk='request_public_key',
    ppk_req='process_public_key_requests',
    ppk_resp='process_public_key_responses'
)


def main():
    global args
    command = args.command
    if command not in COMMANDS:
        alias_command = COMMAND_ALIASES.get(command, None)
        if alias_command is None:
            print(colored("unrecognized command: {}".format(command), "red"))
            sys.exit(1)
        else:
            command = alias_command

    # TODO JHILL: check for username?
    argparser.add_argument("--username", required=False, default=None)

    check_user_exists = True
    if command == 'init_user':
        check_user_exists = False
        pass

    elif command == 'broadcast_user':
        argparser.add_argument("--port", type=int, required=False, default=8050)

    elif command == 'verify_user':
        pass

    elif command == 'ping_user':
        argparser.add_argument("--u2", required=True)

    elif command == 'send_message':
        argparser.add_argument("--u2", required=True)
        argparser.add_argument("--filename", required=True)
        argparser.add_argument("--mime_type", required=False, default='image/png')

    elif command == 'challenge_user':
        argparser.add_argument("--u2", required=True)

    elif command == 'request_public_key':
        argparser.add_argument("--u2", required=True)

    elif command == 'process_public_key_requests':
        pass

    elif command == 'process_public_key_responses':
        pass

    else:
        assert False

    if command not in globals():
        error_exit("{} is unimplemented".format(command))

    massage_args()

    if check_user_exists is True:
        user = User(args.username)
        if user.exists is False:
            print(colored("user {} does not exist".format(args.username), "red"))
        else:
            globals()[command]()
    else:
        globals()[command]()