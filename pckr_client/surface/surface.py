from ..user import User
from ..utilities import command_header, send_frame, normalize_path
from ..utilities import encrypt_rsa, encrypt_symmetric, encrypt_rsa, decrypt_symmetric
from ..utilities import hexstr2bytes, bytes2hexstr, str2hashed_hexstr
from ..frame import Frame
from ..ipcache import IPCache

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from termcolor import colored

import binascii
import json
import os
import socket
import threading
import uuid
import pprint
import random
import time
import sys

class SocketThread(threading.Thread):
    clientsocket = None
    user = None

    def __init__(self, clientsocket, username):
        super(SocketThread, self).__init__()
        self.clientsocket = clientsocket
        self.user = User(username)

        # TODO JHILL: assert the user exists?

    def _receive_ping(self, request):
        return dict(
            success=True,
            message="pong"
        )

    def _receive_seek_user(self, request):
        responded = False

        # 1) try to decrypt the message using our own private key
        # if we can decrypt it we should answer the other host
        try:
            password_decrypted = self.user.private_rsakey.decrypt(hexstr2bytes(request['payload']['password']))

            # now we have to open up the message and challenge that user
            decrypted_text = decrypt_symmetric(hexstr2bytes(request['payload']['host_info']), password_decrypted)
            host_info = json.loads(decrypted_text)

            password = str(uuid.uuid4())
            password_encrypted = bytes2hexstr(encrypt_rsa(password, host_info['public_key']))

            path = os.path.join(self.user.path, "current_ip_port.json")
            data = json.loads(open(path).read())

            our_ip_port = dict(
                ip=data['ip'],
                port=data['port'],
                username=self.user.username
            )

            host_info_encrypted = bytes2hexstr(encrypt_symmetric(
                json.dumps(our_ip_port).encode(),
                password.encode()
            ))

            seek_token_encrypted = bytes2hexstr(encrypt_symmetric(
                host_info['seek_token'],
                password.encode()
            ))

            challenge_text = str(uuid.uuid4())

            challenge_frame = Frame(
                content=dict(
                    from_username=self.user.username,
                    challenge_text=challenge_text
                ),
                action="challenge_user"
            )

            challenge_response = send_frame(challenge_frame, host_info['ip'], int(host_info['port']))
            print(challenge_response)
            encrypted_challenge = hexstr2bytes(challenge_response['encrypted_challenge'])
            decrypted_challenge = self.user.private_rsakey.decrypt(encrypted_challenge).decode()

            if challenge_text != decrypted_challenge:
                return dict(
                    success=False,
                    error='that was us, but we challenged the asking user and they failed'
                )

            ipcache = IPCache(self.user)
            ipcache.set_ip_port(host_info['from_username'], host_info['ip'], int(host_info['port']))
            response_dict = dict(
                seek_token=seek_token_encrypted,
                password=password_encrypted,
                host_info=host_info_encrypted
            )

            # now send back a response
            frame = Frame(
                action='seek_user_response',
                content=response_dict
            )

            response = send_frame(frame, host_info['ip'], int(host_info['port']))

            # TODO JHILL: we can also put that host_info into our own ipcache...
            responded = True

        except ValueError as e:
            pass

        if responded == False:
            # 2) if we can't decrypt and respond we should pass the message along
            ipcache = IPCache(self.user)
            count = 0

            request['payload']['custody_chain'].append(
                str2hashed_hexstr(self.user.username)
            )

            for k, v in ipcache.data.items():
                hashed_username = str2hashed_hexstr(k)
                if hashed_username not in request['payload']['custody_chain']:
                    frame = Frame(
                        action=request['action'],
                        message_id=request['message_id'],
                        content=request['payload'],
                    )
                    response = send_frame(frame, v['ip'], int(v['port']))
                    count = count + 1
                else:
                    print("skipping")

            return dict(success=True, message="propagated to {} other clients".format(count))
        else:
            return dict(success=True, message="that was me, a seek_user_response is imminent")

    def _receive_request_public_key(self, request):
        self.user.store_public_key_request(request)

        # TODO JHILL: make this nicer
        return dict(
            success=True,
            message_id=request['message_id']
        )


    def _receive_public_key_response(self, request):
        self.user.store_public_key_response(request) 
        return dict(success=True, message_id=request['message_id'])


    def _receive_challenge_user(self, request):
        # TODO JHILL: obviously this could fail if we don't know their public_key
        # TODO JHILL: also be more careful about charging into dictionaries
        public_key_text = self.user.get_contact_public_key(request["payload"]["from_username"])

        if public_key_text is None:
            return dict(success=False, error="we don't have the asking users public_key so this won't work at all")
        else:
            challenge_rsaed = bytes2hexstr(encrypt_rsa(request["payload"]["challenge_text"], public_key_text))

            return dict(
                success=True,
                encrypted_challenge=challenge_rsaed
            )


    def _receive_send_message(self, request):
        # TODO JHILL: definitely put this all away behind a message object
        print(request)

        # TODO JHILL: get the key from the user object?
        # TODO JHILL: a function to just get a message key?
        if request['payload']['mime_type'] == 'image/png':
            filename = "out.png"
        else:
            filename = "out.txt"

        # TODO JHILL: make this better.... maybe have a transfer facade?
        path = os.path.join(self.user.messages_path, request['message_id'])
        if not os.path.exists(path):
            os.makedirs(path)
        path = os.path.join(path, filename)

        # TODO JHILL: obviously split the handling on binary or not, mime_types!
        # and yeah this would be as good a time as any to introduce a transfer object
        if payload['mime_type'] == 'image/png':
            with open(path, "ab+") as f:
                f.write(hexstr2bytes(request['payload']['content']))
        else:
            with open(path, "a+") as f:
                f.write(payload['content'])

        return dict(
            success=True,
            filename=path
        )

    def _receive_send_message_key(self, request):
        # TODO JHILL: hide this all in the user object or a message object?
        payload = hexstr2bytes(request['payload']['password'])
        payload_data = json.loads(self.user.private_rsakey.decrypt(payload).decode())

        key_path = os.path.join(self.user.message_keys_path, request['message_id'])
        if not os.path.exists(key_path):
            os.makedirs(key_path)

        with open(os.path.join(key_path, "key.json"), "w+") as f:
            f.write(json.dumps(payload_data['content']))

        return dict(
            success=True,
            message_id=request['message_id']
        )

    def _receive_surface_user(self, request):
        password = self.user.private_rsakey.decrypt(hexstr2bytes(request['payload']['password']))
        host_info_decrypted = decrypt_symmetric(
            hexstr2bytes(request['payload']['host_info']),
            password
        )

        print(host_info_decrypted)
        host_info = json.loads(
            host_info_decrypted
        )

        public_key_text = self.user.get_contact_public_key(host_info['from_username'])
        if False: # public_key_text is None:
            return dict(
                success=False,
                error="we don't have their public key, don't care about storing their IP"
            )
        else:
            # TODO JHILL: challenge the user

            # except there has to be two challenges
            # 1) you have my public key
            # 2) this is your public key
            # right now only #1 is implemented, strangely enough
            # clean that up at the same time. for now just store their ip
            # TODO JHILL: SECURITY RISK
            ipcache = IPCache(self.user)
            ipcache.set_ip_port(host_info['from_username'], host_info['ip'], int(host_info['port']))
            return dict(
                success=True
            )

    def _receive_seek_user_response(self, request):
        assert type(request) == dict
        password = self.user.private_rsakey.decrypt(hexstr2bytes(request['payload']['password']))

        seek_token_decrypted = decrypt_symmetric(
            hexstr2bytes(request['payload']['seek_token']),
            password
        )
        host_info_decrypted = decrypt_symmetric(
            hexstr2bytes(request['payload']['host_info']),
            password
        )

        print(seek_token_decrypted)
        print(host_info_decrypted)
        host_info = json.loads(
            host_info_decrypted
        )

        seek_token_path = os.path.join(
            self.user.seek_tokens_path, 
            "{}.json".format(host_info['username'])
        )
        
        # TODO JHILL: error handling obviously
        seek_token_data = json.loads(open(seek_token_path).read())
        print(seek_token_data)
        if seek_token_data['seek_token'] == seek_token_decrypted:
            ipcache = IPCache(self.user)
            ipcache.set_ip_port(host_info['username'], host_info['ip'], int(host_info['port']))

            return dict(
                success=True,
                message_id=request['message_id']
            )
        else:
            return dict(
                success=False,
                error='seek token not found'
            )

    def _receive_pulse_network(self, request):
        self.user.pulse_network(request['payload']['custody_chain'])

        return dict(
            success=True
        )

    def process_request(self, request_text):
        print(colored("*"*100, "blue"))
        request_data = json.loads(request_text)
        print("action: ", colored(request_data['action'], "green"))
        print("request:")
        print(colored(pprint.pformat(request_data), "green"))
        print(colored("*"*100, "blue"))

        if request_data['action'] == 'ping':
            return self._receive_ping(request_data)
        elif request_data['action'] == 'send_message':
            return self._receive_send_message(request_data)
        elif request_data['action'] == 'send_message_key':
            return self._receive_send_message_key(request_data)
        elif request_data['action'] == 'request_public_key':
            return self._receive_request_public_key(request_data)
        elif request_data['action'] == 'public_key_response':
            return self._receive_public_key_response(request_data)
        elif request_data['action'] == 'challenge_user':
            return self._receive_challenge_user(request_data)
        elif request_data['action'] == 'seek_user':
            return self._receive_seek_user(request_data)
        elif request_data['action'] == 'seek_user_response':
            return self._receive_seek_user_response(request_data)
        elif request_data['action'] == 'surface_user':
            return self._receive_surface_user(request_data)
        elif request_data['action'] == 'pulse_network':
            return self._receive_pulse_network(request_data)
        else:
            return dict(
                success=False,
                error="unknown action '{}'".format(request_data['action'])
            )

    def run(self):
        request_text = self.clientsocket.recv(int(65536 / 2)).decode()
        response = self.process_request(request_text)

        if type(response) == dict:
            response = json.dumps(response)
        else:
            print(colored("passing anything but dicts is deprecated", "red"))
            assert False

        print("\n")
        print("response", colored(pprint.pformat(response), "green"))
        print("\n")
        print(colored("*" * 100, "blue"))
        print(colored("* end request", "blue"))
        print(colored("*" * 100, "blue"))
        print("\n")

        self.clientsocket.sendall(response.encode())
        self.clientsocket.close()

class SeekUsersThread(threading.Thread):
    user = None
    def __init__(self, user):
        super(SeekUsersThread, self).__init__()
        self.user = user

    def run(self):
        while True:
            self._seek_users()
            time.sleep(random.randint(20, 40))

    def _seek_users(self):
        path = os.path.join(self.user.path, "current_ip_port.json")
        with open(path, "r") as f:
            current_ip_port = json.loads(open(path).read())

        ipcache = IPCache(self.user)
        for k, v in ipcache.data.items():
            public_key_text = self.user.get_contact_public_key(k)
            if public_key_text is not None:
                self.user.seek_user(k)


class SurfaceUserThread(threading.Thread):
    user = None
    def __init__(self, user):
        super(SurfaceUserThread, self).__init__()
        self.user = user

    def run(self):
        while True:
            self._surface_user()
            time.sleep(random.randint(20, 40))

    def _surface_user(self):
        path = os.path.join(self.user.path, "current_ip_port.json")
        with open(path, "r") as f:
            current_ip_port = json.loads(open(path).read())

        ipcache = IPCache(self.user)
        for k, v in ipcache.data.items():
            public_key_text = self.user.get_contact_public_key(k)
            if public_key_text is not None:
                password = str(uuid.uuid4())
                password_encrypted = bytes2hexstr(encrypt_rsa(password, public_key_text))

                host_info = dict(
                    from_username=self.user.username,
                    ip=current_ip_port['ip'],
                    port=int(current_ip_port['port'])
                )

                host_info_encrypted = bytes2hexstr(encrypt_symmetric(
                    json.dumps(host_info).encode(),
                    password.encode()
                ))

                frame = Frame(
                    content=dict(
                        password=password_encrypted,
                        host_info=host_info_encrypted
                    ),
                    action='surface_user'
                )

                response = send_frame(
                    frame,
                    v['ip'],
                    int(v['port'])
                )


class Surface(threading.Thread):
    login_token = None
    serversocket = None
    hostname = None
    username = None

    def __init__(self, username, port):
        super(Surface, self).__init__()
        self.port = port
        self.username = username

        while True:
            try:
                self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.serversocket.bind((socket.gethostname(), self.port))
                self.serversocket.listen(5)
                break
            except OSError:
                print(colored("trying next port", "yellow"))
                self.port = self.port + 1

        self.hostname = socket.gethostname()

    def run(self):
        while True:
            try:
                (clientsocket, address) = self.serversocket.accept()
                st = SocketThread(clientsocket, self.username)
                st.start()
            except ConnectionAbortedError:
                pass