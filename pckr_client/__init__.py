import socket
import argparse
import os
from Crypto.PublicKey import RSA 
from .broadcaster import Broadcaster
import requests
import json
import keyring
from Crypto.Cipher import PKCS1_OAEP
import binascii
import pprint
from .frame import Frame

argparser = argparse.ArgumentParser()
argparser.add_argument('command')
args, _ = argparser.parse_known_args()


def initiate_user():
    path = os.path.join("~/pckr/", args.number)
    path = os.path.expanduser(path)

    if os.path.exists(path):
        # TODO ALSO CHECK SERVER
        print("already there")
    else:
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
        print(response.json())
        token = response.json()['token']
        keyring.set_password("pckr", args.number, token)

        # the server will send back a response token signed with your
        # public key, this will be your login token that you need to send
        # with every transmission
        # then poeple can query the registry for the ip and port of your number 
        # and get it back
        # safely, knowing only you can listen on that ip and port
        # obviously only communicate over SSL to the coordinating server
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
    bc = Broadcaster(args.port)
    bc.start()
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.post('http://127.0.0.1:5000/user/broadcast/', headers=headers, data=json.dumps(dict(
        phone_number=args.number,
        login_token=token,
        ip=bc.serversocket.getsockname()[0],
        port=bc.port
    )))
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

    print(len(content))
    mime_type = args.mime_type
    frames = Frame.make_frames(content, "send_file", mime_type=mime_type)
    print(len(frames))

    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.get('http://127.0.0.1:5000/users/?number={}'.format(args.other_number), headers=headers).json()
    for frame in frames:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((response['users'][0]['ip'].strip(), response['users'][0]['port']))
        sock.send(str(frame).encode())
        sock_response = sock.recv(1024)
        print(sock_response)
        

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
    
    