from ..user import User
from ..utilities import command_header, send_frame_users, normalize_path, is_binary
from ..utilities import encrypt_rsa, encrypt_symmetric, decrypt_symmetric, decrypt_rsa
from ..utilities import hexstr2bytes, bytes2hexstr, str2hashed_hexstr
from ..frame import Frame
from ..utilities.logging import assert_logger
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
import subprocess
import sys


class SocketThread(threading.Thread):
    clientsocket = None
    user = None

    def __init__(self, clientsocket, username):
        super(SocketThread, self).__init__()
        self.clientsocket = clientsocket
        self.user = User(username)

    def _receive_ping(self, request):
        """
        receive the ping request and respond with a pong message
        """

        assert type(request) == dict

        return dict(
            success=True,
            message="pong"
        )

    def _receive_seek_user(self, request):
        """
        receive the seek_user request. try to decrypt the message contained in it
        and respond to the user that was seeking you if you can
        """

        assert type(request) == dict
        assert 'payload' in request, 'payload not in request'

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

            u2 = host_info['from_username']
            ip, port = self.user.get_contact_ip_port(u2)
            self.user.set_contact_ip_port(u2, host_info['ip'], host_info['port'])

            ping = self.user.ping_user(u2)
            if ping is False:
                self.user.set_contact_ip_port(u2, ip, port)

                return dict(
                    success=False,
                    error='that was us, but the asking user is unreachable'
                )

            # ask them if they have our public key
            # maybe we should ask them to prove their public key, as well
            challenge = self.user.challenge_user_has_pk(u2)
            if challenge is False:
                self.user.set_contact_ip_port(u2, ip, port)

                return dict(
                    success=False,
                    error='that was us, but we challenged the asking user and they failed'
                )

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
                u2,
                host_info['ip'],
                int(host_info['port'])
            )
            response = send_frame_users(frame, self.user, u2)

            responded = True

        except ValueError as e:
            pass

        if responded == False:
            if len(request['payload']['custody_chain']) > 4:
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
        assert type(request) == dict, 'request is not dict'

        self.user.store_public_key_request(request)
        self.user.store_voluntary_public_key(request)

        return dict(
            success=True
        )


    def _receive_public_key_response(self, request):
        assert type(request) == dict, 'request is not dict'

        self.user.store_public_key_response(request) 

        return dict(
            success=True
        )

    def _receive_challenge_user_pk(self, request):
        assert type(request) == dict, "request is not dict"
        assert 'payload' in request, "payload not in request"
        assert 'challenge_text' in request['payload'], "challenge_text not in request['payload']"

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
        assert type(request) == dict
        assert 'payload' in request
        assert 'from_username' in request['payload']
        assert 'challenge_text' in request['payload']

        public_key_text = self.user.get_contact_public_key(request["payload"]["from_username"])

        if public_key_text is None:
            return dict(
                success=False,
                error="we don't have the asking users public_key so this won't work at all"
            )
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
        key = None
        key_path = os.path.join(self.user.message_keys_path, meta['message_id'])
        with open(os.path.join(key_path, "key.json"), "r") as f:
            key = json.loads(f.read())

        path = os.path.join(self.user.messages_path, meta['message_id'])
        if not os.path.exists(path):
            os.makedirs(path)
        filename = os.path.basename(os.path.normpath(meta['filename']))
        path = os.path.join(path, filename)

        if is_binary(meta['mime_type']):
            content_decrypted = decrypt_symmetric(
                hexstr2bytes(request['payload']['content']),
                key['password'],
                decode=False
            )
            print(content_decrypted)

            with open(path, "ab+") as f:
                f.write(content_decrypted)
        else:
            content_decrypted = decrypt_symmetric(
                hexstr2bytes(content),
                key['password']
            )

            with open(path, "a+") as f:
                f.write(content_decrypted)

        return dict(
            success=True
        )

    def _receive_send_message_term(self, request):
        assert type(request) == dict, 'request must be a dict'
        assert 'payload' in request, 'payload not in request'
        assert 'password' in request['payload'], "password not in request['payload']"
        assert 'term' in request['payload'], "term not in request['payload']"

        password_decrypted = decrypt_rsa(
            hexstr2bytes(request['payload']['password']),
            self.user.private_key_text
        )

        term_decrypted = decrypt_symmetric(
            hexstr2bytes(request['payload']['term']),
            password_decrypted
        )

        term = json.loads(term_decrypted)
        path = os.path.join(self.user.messages_path, term['message_id'])
        filename = os.path.basename(os.path.normpath(term['filename']))
        path = os.path.join(path, filename)

        """
        path = path
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
        """
        print("wrote to", path)

        subprocess.check_call([
            "open",
            path
        ])

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
            success=True
        )

    def _receive_surface_user(self, request):
        assert type(request) == dict, 'request must be a dict'
        assert 'payload' in request, 'payload not in request'
        assert 'password' in request['payload'], "password not in request['payload']"
        assert 'host_info' in request['payload'], "host_info not in request['payload']"

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

        assert 'username' in host_info
        assert 'ip' in host_info
        assert 'port' in host_info

        public_key_text = self.user.get_contact_public_key(host_info['from_username'])
        if public_key_text is None:
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
            self.user.set_contact_ip_port(
                host_info['from_username'],
                host_info['ip'],
                int(host_info['port'])
            )

            return dict(
                success=True
            )

    def _receive_seek_user_response(self, request):
        assert type(request) == dict, 'request must be a dict'
        assert 'payload' in request, 'payload not in request'
        assert 'password' in request['payload'], "password not in request['payload']"
        assert 'seek_token' in request['payload'], "seek_token not in request['payload']"
        assert 'host_info' in request['payload'], "host_info not in request['payload']"

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

        assert 'username' in host_info
        assert 'ip' in host_info
        assert 'port' in host_info

        seek_token_path = os.path.join(
            self.user.seek_tokens_path,
            "{}.json".format(host_info['username'])
        )

        seek_tokens = []
        try:
            seek_tokens = json.loads(open(seek_token_path).read())
        except FileNotFoundError as e:
            return dict(
                success=False,
                error='seek_tokens not found'
            )

        # TODO JHILL: this could be a one-liner using 'in' but you need to test it again
        found = False
        for x in seek_tokens:
            if x.strip() == seek_token_decrypted.strip():
                found = True

        if found:
            self.user.set_contact_ip_port(
                host_info['username'],
                host_info['ip'],
                int(host_info['port'])
            )

            return dict(
                success=True
            )
        else:
            return dict(
                success=False,
                error='seek_token not found'
            )


    def _receive_pulse_network(self, request):
        assert type(request) == dict, "request must be a dict"
        assert 'payload' in request, "payload not in request"
        assert 'custody_chain' in request['payload'], "custody_chain not in request['payload']"

        self.user.pulse_network(request['payload']['custody_chain'])

        return dict(
            success=True
        )


    def _receive_check_net_topo(self, request):
        assert type(request) == dict, "request must be a dict"
        assert 'payload' in request, "payload not in request"
        assert 'custody_chain' in request['payload'], "custody_chain not in request['payload']"
        assert 'hashed_ipcaches' in request['payload'], "hashed_ipcaches not in request['payload']"
        assert type(request['payload']['hashed_ipcaches']) is dict, "hashed_ipcaches must be a dict"

        self.user.check_net_topo(
            request['payload']['custody_chain'],
            request['payload']['hashed_ipcaches']
        )

        return dict(
            success=True,
        )
    
    def _receive_net_topo_damaged(self, request):
        assert type(request) == dict, "request must be a dict"
        assert 'payload' in request, "payload not in request"
        assert 'inconsistent_user' in request['payload'], "custody_chain not in request['payload']"

        self.user.flush_inconsistent_user(request['payload']['inconsistent_user'])

        return dict(
            success=True
        )

    def process_request(self, request):
        print(colored("*"*100, "blue"))
        print("action: ", colored(request['action'], "green"))
        print("request:")
        print(colored(pprint.pformat(request), "green"))
        print(colored("*"*100, "blue"))

        try:
            assert 'action' in request, 'request has no action'

            if request['action'] == 'ping':
                return self._receive_ping(request)
            elif request['action'] == 'send_message':
                return self._receive_send_message(request)
            elif request['action'] == 'send_message_key':
                return self._receive_send_message_key(request)
            elif request['action'] == 'send_message_term':
                return self._receive_send_message_term(request)
            elif request['action'] == 'request_public_key':
                return self._receive_request_public_key(request)
            elif request['action'] == 'public_key_response':
                return self._receive_public_key_response(request)
            elif request['action'] == 'challenge_user_has_pk':
                return self._receive_challenge_user_has_pk(request)
            elif request['action'] == 'challenge_user_pk':
                return self._receive_challenge_user_pk(request)
            elif request['action'] == 'seek_user':
                return self._receive_seek_user(request)
            elif request['action'] == 'seek_user_response':
                return self._receive_seek_user_response(request)
            elif request['action'] == 'surface_user':
                return self._receive_surface_user(request)
            elif request['action'] == 'pulse_network':
                return self._receive_pulse_network(request)
            elif request['action'] == 'check_net_topo':
                return self._receive_check_net_topo(request)
            elif request['action'] == 'net_topo_damaged':
                return self._receive_net_topo_damaged(request)

            else:
                return dict(
                    success=False,
                    error="unknown action '{}'".format(request['action'])
                )
        except AssertionError as e:
            assert_logger.error(e)

            return dict(
                success=False,
                error=str(e)
            )
        except json.decoder.JSONDecodeError as e:
            print(e)
            return dict(
                success=False,
                error=str(e)
            )

    def run(self):
        request_text = self.clientsocket.recv(int(65536 / 2)).decode()
        try:
            request = json.loads(request_text)
            response = self.process_request(request)
        except json.decoder.JSONDecodeError as e:
            print(request_text)
            print(e)
            return dict(
                success=False,
                error=str(e)
            )

        assert 'frame_id' in request
        response.update(response_to_frame=request['frame_id'])

        if type(response) == dict:
            response = json.dumps(response)
        else:
            print(colored("passing anything but dicts is deprecated", "red"))
            assert False


        print("\n")
        print("response", colored(response, "green"))
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
            success, interval = self._seek_users()
            time.sleep(random.randint(interval, interval * 2))

    def _seek_users(self):
        """
        seek out all of the other users that self.user knows about
        ping them first.... if they fail that, seek them
        if they pass the ping, challenge them
        if they fail the challenge, then remove them from the ipcache and seek them
        failing the challenge is bad so we should get rid of them and try to find the
        real user again
        """

        # TODO JHILL: we should also seek out all of the users that we have public_keys for, that
        # we don't have in our ipcache.... makes sense to be connected if we can

        # iterate through all of the cached ips that we have, and check if the users are still there
        # first ping them.... if they pass the ping, challenge them.
        # if they fail the ping, seek them out
        # if they fail the challenge after the ping, remove them from the ipcache
        # and seek them out
        for k in self.user.ipcache.keys():
            print(colored("*" * 100, "cyan"))
            print(colored("* {} pinging {}".format(self.user.username, k), "cyan"))
            ping = self.user.ping_user(k)

            if ping is False:
                print(colored("* seeking them because they failed the ping", "cyan"))
                self.user.seek_user(k)
            else:
                public_key_text = self.user.get_contact_public_key(k)
                if public_key_text:
                    print(colored("* {} challenging {}".format(self.user.username, k), "cyan"))
                    challenge = self.user.challenge_user_pk(k)

                    if challenge is True:
                        print(colored("* challenge passed", "cyan"))
                        print(colored("*" * 100, "cyan"))

                    else:
                        print(colored("* removing and seeking them because they failed the challenge", "cyan"))
                        self.user.remove_contact_ip_port(k)
                        self.user.seek_user(k)
                else:
                    print(colored("* we don't have their public_key", "cyan"))
            print(colored("*" * 100, "cyan"))

        return True, 60


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