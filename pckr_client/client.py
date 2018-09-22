from .surface import Surface, SurfaceUserThread, SeekUsersThread
from .frame import Frame
from .ipcache import IPCache
from .user import User
from .utilities import hexstr2bytes, bytes2hexstr, str2hashed_hexstr
from .utilities import encrypt_rsa, encrypt_symmetric, decrypt_rsa
from .utilities import command_header, send_frame

from termcolor import colored

import argparse
import os
import pprint
import uuid
import sys
import json


def init_user(args):
    user = User(args.username)

    if user.exists:
        # TODO JHILL: ALSO CHECK SERVER
        print(colored("this user already exists: {}".format(args.username), "red"))
    else:
        user.initiate_directory_structure()
        user.initiate_rsa()
        print(colored("created user: {}".format(args.username), "green"))

    return True


def challenge_user(args):
    user = User(args.username)
    challenge_text = str(uuid.uuid4())

    frame = Frame(
        content=dict(
            from_username=args.username,
            challenge_text=challenge_text
        ),
        action="challenge_user"
    )

    ipcache = IPCache(user)
    (ip, port) = ipcache.get_ip_port(args.u2)
    response = send_frame(frame, ip, port)
    print(response)

    if response['success'] is True:
        # TODO JHILL: check return for success or not...
        # don't just charge through it

        decrypted_challenge = decrypt_rsa(
            hexstr2bytes(response['encrypted_challenge']),
            user.private_key_text
        )

        print(colored(challenge_text, "blue"))
        print(colored(decrypted_challenge, "blue"))

        if challenge_text == decrypted_challenge:
            print(colored("good", "green"))
    else:
        print(colored(response['error'], "red"))


def request_public_key(args):
    user = User(args.username)

    frame = Frame(
        content=dict(
            from_username=args.username,
            public_key=user.public_key_text
        ), 
        action="request_public_key"
    )

    ipcache = IPCache(user)
    (ip, port) = ipcache.get_ip_port(args.u2)

    response = send_frame(frame, ip, port)
    pprint.pprint(response, indent=4)


def surface_user(args):
    # TODO JHILL: verify the user exists, both here and on the server!
    surface = Surface(args.username, args.port)
    surface.start()

    path = os.path.expanduser("~/pckr/surfaced.json")
    data = dict()
    try:
        data = json.loads(open(path).read())
    except:
        pass

    data[args.username] = dict(
        ip=surface.serversocket.getsockname()[0],
        port=surface.port
    )

    with open(path, "w+") as f:
        f.write(json.dumps(data))

    user = User(args.username)
    path = os.path.join(user.path, "current_ip_port.json")
    with open(path, "w+") as f:
        f.write(json.dumps(dict(ip=surface.serversocket.getsockname()[0], port=surface.port)))

    # TODO JHILL: surface to all users in ipcache
    print(colored("surfaced on {}:{}".format(surface.serversocket.getsockname()[0], surface.port), "green"))

    surface_user_thread = SurfaceUserThread(user)
    surface_user_thread.start()

    seek_users_thread = SeekUsersThread(user)
    seek_users_thread.start()
    
    seek_users_thread.join()
    surface_user_thread.join()
    surface.join()


def add_ipcache(args):
    user = User(args.username)

    ipcache = IPCache(user)
    ipcache.set_ip_port(args.u2, args.ip, args.port)
    print(ipcache)


def remove_ipcache(args):
    user = User(args.username)

    ipcache = IPCache(user)
    ipcache.remove_ip_port(args.u2)
    print(ipcache)


def seek_user(args):
    user = User(args.username)
    user.seek_user(args.u2)


def ping_user(args):
    user = User(args.username)
    ipcache = IPCache(user)
    (ip, port) = ipcache.get_ip_port(args.u2)

    frame = Frame(content=dict(), action="ping")
    response = send_frame(frame, ip, port)
    pprint.pprint(response, indent=4)


def send_message(args):
    import time
    t = time.time()
    
    # TODO JHILL: challenge the user first
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

    password = str(uuid.uuid4())
    message_id = str(uuid.uuid4())
    password_encrypted = bytes2hexstr(encrypt_rsa(password, public_key_text))

    ipcache = IPCache(user)
    ip, port = ipcache.get_ip_port(args.u2)

    key_frame = Frame(
        action='send_message_key',
        content=dict(
            password=password_encrypted
        ),
        message_id=message_id
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


def process_public_key_responses(args):
    user = User(args.username)
    for response in user.public_key_responses:
        if user.process_public_key_response(response):
            user.remove_public_key_response(response)


def process_public_key_requests(args):
    user = User(args.username)
    for request in user.public_key_requests:
        if user.process_public_key_request(request):
            user.remove_public_key_request(request)


def pulse_network(args):
    user = User(args.username)
    assert user.exists

    user.pulse_network()


def massage_args(argparser):
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
    return argparser.parse_args()


COMMANDS = [
    'init_user',
    'surface_user',
    'seek_user',
    'ping_user',
    'send_message',
    'challenge_user',
    'request_public_key',
    'process_public_key_requests',
    'process_public_key_responses',
    'add_ipcache',
    'remove_ipcache',
    'pulse_network'
]


COMMAND_ALIASES = dict(
    iu='init_user',
    surface='surface_user',
    seek='seek_user',
    pu='ping_user',
    sm='send_message',
    cu='challenge_user',
    rpk='request_public_key',
    ppk_req='process_public_key_requests',
    ppk_resp='process_public_key_responses',
    aip='add_ipcache',
    rip='remove_ipcache',
    pn='pulse_network'
)


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('command')
    args, _ = argparser.parse_known_args()
    
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
    
    elif command == 'seek_user':
        argparser.add_argument("--u2", required=True)
        
    elif command == 'surface_user':
        argparser.add_argument("--port", type=int, required=False, default=8050)

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

    elif command == 'add_ipcache':
        argparser.add_argument("--u2", required=True)
        argparser.add_argument("--ip", required=True)
        argparser.add_argument("--port", required=True)

    elif command == 'remove_ipcache':
        argparser.add_argument("--u2", required=True)
    
    elif command == 'pulse_network':
        pass

    else:
        assert False

    if command not in globals():
        error_exit("{} is unimplemented".format(command))

    args = massage_args(argparser)
    print(command_header(command, args))

    if check_user_exists is True:
        user = User(args.username)
        if user.exists is False:
            print(colored("user {} does not exist".format(args.username), "red"))
        else:
            globals()[command](args)
    else:
        globals()[command](args)

    print("\n")
    print(colored("*" * 100, "blue"))
    print(colored("* end command", "blue"))
    print(colored("*" * 100, "blue"))
    print("\n")
