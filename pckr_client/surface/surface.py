from ..user import User
from ..utilities import command_header, send_frame_users, normalize_path, is_binary
from ..utilities import encrypt_rsa, encrypt_symmetric, decrypt_symmetric, decrypt_rsa
from ..utilities import hexstr2bytes, bytes2hexstr, str2hashed_hexstr
from ..frame import Frame

from termcolor import colored

import binascii
import datetime
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
            password_decrypted = decrypt_rsa(
                hexstr2bytes(request['payload']['password']),
                self.user.private_key_text
            )

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

            challenge = self.user.challenge_user_has_pk(host_info['from_username'])
            if challenge is False:
                return dict(
                    success=False,
                    error='that was us, but we challenged the asking user and they failed'
                )

            user.set_contact_ip_port(host_info['from_username'], host_info['ip'], int(host_info['port']))
            response_dict = dict(
                seek_token=seek_token_encrypted,
                password=password_encrypted,
                host_info=host_info_encrypted
            )

            # now send back a response
            frame = Frame(
                action='seek_user_response',
                payload=response_dict
            )
            
            self.user.set_contact_ip_port(
                host_info['from_username'],
                host_info['ip'],
                int(host_info['port'])
            )
            response = send_frame_users(frame, self.user, host_info['from_username'])

            responded = True

        except ValueError as e:
            pass

        if responded == False:
            if len(request['payload']['custody_chain']) > 3:
                return dict(success=True, message='custody_chain len exceeded')

            # 2) if we can't decrypt and respond we should pass the message along
            count = 0

            request['payload']['custody_chain'].append(
                str2hashed_hexstr(self.user.username)
            )

            for k, _ in self.user.ipcache.items():
                hashed_username = str2hashed_hexstr(k)
                if hashed_username not in request['payload']['custody_chain']:
                    frame = Frame(
                        action=request['action'],
                        payload=request['payload'],
                    )
                    response = send_frame_users(frame, self.user, k)
                    count = count + 1

            return dict(success=True, message="propagated to {} other clients".format(count))
        else:
            return dict(success=True, message="that was me, a seek_user_response is imminent")

    def _receive_request_public_key(self, request):
        self.user.store_public_key_request(request)
        self.user.store_voluntary_public_key(request)

        # TODO JHILL: make this nicer
        return dict(
            success=True,
            frame_id=request['frame_id']
        )


    def _receive_public_key_response(self, request):
        self.user.store_public_key_response(request) 
        return dict(success=True, frame_id=request['frame_id'])

    def _receive_challenge_user_pk(self, request):
        try:
            decrypted = decrypt_rsa(
                hexstr2bytes(request['payload']['challenge_text']),
                self.user.private_key_text
            )

            return dict(
                success=True,
                decrypted_challenge=decrypted.decode()
            )
        except ValueError:
            return dict(
                success=False,
                error="that isn't my public key apparently"
            )

    def _receive_challenge_user_has_pk(self, request):
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
        password_decrypted = decrypt_rsa(
            hexstr2bytes(request['payload']['password']),
            self.user.private_key_text
        )
        
        meta_decrypted = decrypt_symmetric(
            hexstr2bytes(request['payload']['meta']),
            password_decrypted
        )

        meta = json.loads(meta_decrypted)
        path = os.path.join(self.user.messages_path, meta['message_id'])
        if not os.path.exists(path):
            os.makedirs(path)
        path = os.path.join(path, meta['filename'])

        with open(path, "w+") as f:
            f.write(request['payload']['content'])

        return dict(
            success=True
        )

    def _receive_send_message_term(self, request):
        password_decrypted = decrypt_rsa(
            hexstr2bytes(request['payload']['password']),
            self.user.private_key_text
        )

        term_decrypted = decrypt_symmetric(
            hexstr2bytes(request['payload']['term']),
            password_decrypted
        )

        term = json.loads(term_decrypted)

        key = None
        key_path = os.path.join(self.user.message_keys_path, term['message_id'])
        with open(os.path.join(key_path, "key.json"), "r") as f:
            key = json.loads(f.read())

        path = os.path.join(self.user.messages_path, term['message_id'])
        path = os.path.join(path, term['filename'])

        content = open(path).read()

        if is_binary(term['mime_type']):
            content_decrypted = decrypt_symmetric(
                hexstr2bytes(content),
                key['password'],
                decode=False
            )

            with open(path, "wb+") as f:
                f.write(content_decrypted)
        else:
            content_decrypted = decrypt_symmetric(
                hexstr2bytes(content),
                key['password']
            )

            with open(path, "w+") as f:
                f.write(content_decrypted)

        return dict(
            success=True
        )

    def _receive_send_message_key(self, request):
        print(request)

        password_decrypted = decrypt_rsa(
            hexstr2bytes(request['payload']['password']),
            self.user.private_key_text
        )

        key_decrypted = decrypt_symmetric(
            hexstr2bytes(request['payload']['key']),
            password_decrypted
        )

        key = json.loads(key_decrypted)

        key_path = os.path.join(self.user.message_keys_path, key['message_id'])
        if not os.path.exists(key_path):
            os.makedirs(key_path)

        with open(os.path.join(key_path, "key.json"), "w+") as f:
            f.write(json.dumps(key))

        return dict(
            success=True,
            frame_id=request['frame_id']
        )

    def _receive_surface_user(self, request):
        password = decrypt_rsa(
            hexstr2bytes(request['payload']['password']),
            self.user.private_key_text
        )

        host_info_decrypted = decrypt_symmetric(
            hexstr2bytes(request['payload']['host_info']),
            password
        )

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
            self.user.set_contact_ip_port(host_info['from_username'], host_info['ip'], int(host_info['port']))
            return dict(
                success=True
            )

    def _receive_seek_user_response(self, request):
        assert type(request) == dict
        password = decrypt_rsa(
            hexstr2bytes(request['payload']['password']),
            self.user.private_key_text
        )

        seek_token_decrypted = decrypt_symmetric(
            hexstr2bytes(request['payload']['seek_token']),
            password
        )
        host_info_decrypted = decrypt_symmetric(
            hexstr2bytes(request['payload']['host_info']),
            password
        )

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
            self.user.set_contact_ip_port(host_info['username'], host_info['ip'], int(host_info['port']))
            os.remove(seek_token_path)
            return dict(
                success=True,
                frame_id=request['frame_id']
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
        elif request_data['action'] == 'send_message_term':
            return self._receive_send_message_term(request_data)
        elif request_data['action'] == 'request_public_key':
            return self._receive_request_public_key(request_data)
        elif request_data['action'] == 'public_key_response':
            return self._receive_public_key_response(request_data)
        elif request_data['action'] == 'challenge_user_has_pk':
            return self._receive_challenge_user_has_pk(request_data)
        elif request_data['action'] == 'challenge_user_pk':
            return self._receive_challenge_user_pk(request_data)
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
        time.sleep(10)
        while True:
            success, interval = self._seek_users()
            time.sleep(random.randint(interval, interval * 2))

    def _seek_users(self):
        for k in self.user.ipcache.keys():
            challenge = self.user.challenge_user_pk(k)

            if challenge is True:
                print("she was there all along")
                return True, 60
            else:
                print("can't find her so we'll remove and seek")
                # self.user.remove_contact_ip_port(k)
                self.user.seek_user(k)

        # TODO JHILL: take them out of the ip cache.... but they should be in here
        # will also need to remove the seek token file if we do it this way
        # after the token has been used
        # TODO JHILL: attach file dates to all of the seek tokens,
        # and reseek people if it's been more than 2 or 3 minutes since we started
        for st in self.user.seek_tokens:
            print("gonna seek?", st)
            sleep_time = (datetime.datetime.now() - st['modified_at']).total_seconds()
            print(sleep_time)
            if  sleep_time > 5:
                print("yes")
                self.user.seek_user(st['username'])
            else:
                print("not yet")

        return True, 5


class SurfaceUserThread(threading.Thread):
    user = None
    def __init__(self, user):
        super(SurfaceUserThread, self).__init__()
        self.user = user

    def run(self):
        self.user.surface()
        return True


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