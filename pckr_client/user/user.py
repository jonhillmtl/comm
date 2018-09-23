from ..frame import Frame
from ..utilities import command_header, send_frame_users, normalize_path
from ..utilities import encrypt_rsa, encrypt_symmetric, encrypt_rsa, decrypt_symmetric, decrypt_rsa, generate_rsa_pub_priv
from ..utilities import hexstr2bytes, bytes2hexstr, str2hashed_hexstr

import binascii
import json
import os
import uuid
import pprint
import datetime


USER_ROOT = "~/pckr/"

class User(object):
    username = None
    ipcache_data = None

    def __init__(self, username):
        self.username = username

        ipcache_path = os.path.join(self.ipcache_path, "cache.json")
        ipcache_data = dict()
        if os.path.exists(ipcache_path):
            try:
                ipcache_data = json.loads(open(ipcache_path).read())
            except json.decoder.JSONDecodeError:
                pass
        self.ipcache_data = ipcache_data
    
    def __str__(self):
        return self.username

    @property
    def exists(self):
        return os.path.exists(self.path)

    @property
    def path(self):
        return normalize_path(os.path.join(USER_ROOT, self.username))

    @property
    def public_key_text(self):
        return open(self.public_key_path).read()

    @property
    def public_key_path(self):
        return os.path.join(self.path, "public.key")

    @property
    def public_keys_path(self):
        return os.path.join(self.path, "public_keys")

    @property
    def private_key_path(self):
        return os.path.join(self.path, "private.key")

    @property
    def current_ip_port(self):
        # TODO JHILL: memoize
        try:
            return json.loads(open(os.path.join(self.path, "current_ip_port.json")).read())
        except FileNotFoundError:
            return None

    @property
    def private_key_text(self):
        return open(self.private_key_path).read()

    @property
    def messages_path(self):
        return os.path.join(self.path, "messages")

    @property
    def message_keys_path(self):
        return os.path.join(self.path, "message_keys")

    def pulse_network(self, custody_chain=[]):
        custody_chain.append(str2hashed_hexstr(self.username))

        for k in self.ipcache.keys():
            hashed_username = str2hashed_hexstr(k)
            if hashed_username not in custody_chain:
                frame = Frame(payload=dict(
                    custody_chain=custody_chain
                ), action='pulse_network')

                response = send_frame_users(frame, self, k)

        return True

    def surface(self):
        for k in self.ipcache.keys():
            public_key_text = self.get_contact_public_key(k)
            if public_key_text is not None:
                password = str(uuid.uuid4())
                password_encrypted = bytes2hexstr(encrypt_rsa(password, public_key_text))

                host_info = dict(
                    from_username=self.username,
                    ip=self.current_ip_port['ip'],
                    port=int(self.current_ip_port['port'])
                )

                host_info_encrypted = bytes2hexstr(encrypt_symmetric(
                    json.dumps(host_info).encode(),
                    password.encode()
                ))

                frame = Frame(
                    payload=dict(
                        password=password_encrypted,
                        host_info=host_info_encrypted
                    ),
                    action='surface_user'
                )

                response = send_frame_users(
                    frame,
                    self,
                    k
                )

        return True

    #----------------------------------------------------------------------------------------
    #
    # public_key_request 
    # public_key_requests
    #
    #-----------------------------------------------------------------------------------------
    @property
    def seek_tokens_path(self):
        return os.path.join(self.path, "seek_tokens")

    @property
    def seek_tokens(self):
        sts = []
        for sd in os.listdir(self.seek_tokens_path):
            path = os.path.join(self.seek_tokens_path, sd)
            sts.append(dict(
                username=sd.split('.')[0],
                modified_at=datetime.datetime.fromtimestamp(os.path.getmtime(path)))
            )
        return sts

    def seek_user(self, u2):
        public_key_text = self.get_contact_public_key(u2)
        if public_key_text is None:
            return False

        seek_token = str(uuid.uuid4())
        seek_token_path = os.path.join(self.seek_tokens_path, "{}.json".format(u2))
        with open(seek_token_path, "w+") as f:
            f.write(json.dumps(
                dict(seek_token=seek_token)
            ))

        host_info = dict(
            ip=self.current_ip_port['ip'],
            port=self.current_ip_port['port'],
            public_key=self.public_key_text,
            from_username=self.username,
            seek_token=seek_token
        )

        password = str(uuid.uuid4())
        password_encrypted = bytes2hexstr(encrypt_rsa(password, public_key_text))

        encrypted_host_info = bytes2hexstr(encrypt_symmetric(
            json.dumps(host_info).encode(),
            password.encode()
        ))

        # send the message out to everyone we know
        for k in self.ipcache.keys():
            frame = Frame(payload=dict(
                host_info=encrypted_host_info,
                password=password_encrypted,
                custody_chain=[str2hashed_hexstr(self.username)]
            ), action='seek_user')

            response = send_frame_users(frame, self, k)

        return True

    def get_contact_public_key(self, contact):
        try:
            path = os.path.join(self.public_keys_path, contact, "public.key")
            return open(path).read()
        except FileNotFoundError as e:
            return None

    def init_directory_structure(self):
        assert os.path.exists(self.path) is False
        os.makedirs(self.path)

        assert os.path.exists(self.public_key_requests_path) is False
        os.makedirs(self.public_key_requests_path)

        assert os.path.exists(self.public_key_responses_path) is False
        os.makedirs(self.public_key_responses_path)

        assert os.path.exists(self.public_keys_path) is False
        os.makedirs(self.public_keys_path)

        assert os.path.exists(self.messages_path) is False
        os.makedirs(self.messages_path)
        
        assert os.path.exists(self.message_keys_path) is False
        os.makedirs(self.message_keys_path)

        assert os.path.exists(self.ipcache_path) is False
        os.makedirs(self.ipcache_path)

        assert os.path.exists(self.seek_tokens_path) is False
        os.makedirs(self.seek_tokens_path)

        return True

    def init_rsa(self):
        new_key = generate_rsa_pub_priv()
        with open(self.public_key_path, "wb") as f:
            f.write(new_key.publickey().exportKey("PEM") )

        with open(self.private_key_path, "wb") as f:
            f.write(new_key.exportKey("PEM"))

        return True

    def ping_user(self, u2):
        frame = Frame(action="ping", payload=dict())
        response = send_frame_users(frame, self, u2)
        return response['success']

    #----------------------------------------------------------------------------------------
    #
    # challenge challenges
    # challenge_user_pk
    # challenge_user_pk
    #
    #-----------------------------------------------------------------------------------------
    def challenge_user_pk(self, u2):
        challenge_text = str(uuid.uuid4())

        # TODO JHILL: this isn't necessarily a failure if we don't have their public_key
        public_key_text = self.get_contact_public_key(u2)
        if public_key_text is not None:
            challenge_text_encrypted = bytes2hexstr(encrypt_rsa(
                challenge_text,
                public_key_text
            ))

            frame = Frame(
                payload=dict(
                    from_username=self.username,
                    challenge_text=challenge_text_encrypted
                ),
                action="challenge_user_pk"
            )

            response = send_frame_users(frame, self, u2)
            if response['success'] is True and response['decrypted_challenge'] == challenge_text:
                return True

        return False

    def challenge_user_has_pk(self, u2):
        challenge_text = str(uuid.uuid4())

        frame = Frame(
            payload=dict(
                from_username=self.username,
                challenge_text=challenge_text
            ),
            action="challenge_user_has_pk"
        )

        response = send_frame_users(frame, self, u2)

        if response['success'] is True:
            decrypted_challenge = decrypt_rsa(
                hexstr2bytes(response['encrypted_challenge']),
                self.private_key_text
            )

            if challenge_text == decrypted_challenge:
                return True

        return False

    #----------------------------------------------------------------------------------------
    #
    # public_key_request 
    # public_key_requests
    #
    #-----------------------------------------------------------------------------------------
    @property
    def public_key_requests_path(self):
        return os.path.join(self.path, "public_key_requests")

    @property
    def public_key_requests(self):
        requests = []
        for d, sds, files in os.walk(self.public_key_requests_path):
            for f in files:
                if f[-5:] == '.json':
                    request_path = os.path.join(d, f)
                    with open(request_path) as f:
                        request = json.loads(f.read())
                        request.update(modified_at=datetime.datetime.fromtimestamp(os.path.getmtime(request_path)))
                        requests.append(request)
        return requests

    def store_voluntary_public_key(self, request):
        public_keys_path = os.path.join(self.public_keys_path, request['payload']['from_username'])
        if not os.path.exists(public_keys_path):
            os.makedirs(public_keys_path)

        public_key_path = os.path.join(public_keys_path, 'public.key')
        with open(public_key_path, "w+") as pkf:
            pkf.write(request['payload']['public_key'])

        return True

    def store_public_key_request(self, request):
        request_path = os.path.join(
            self.public_key_requests_path,
            request['payload']['from_username']
        )
        if not os.path.exists(request_path):
            os.makedirs(request_path)

        with open(os.path.join(request_path, "request.json"), "w+") as f:
            f.write(json.dumps(request['payload']))

        return True

    def process_public_key_request(self, request):
        print("request_public_key message from: {}".format(request['from_username']))
        print(request)

        password = str(uuid.uuid4())
        password_rsaed = bytes2hexstr(encrypt_rsa(password, request['public_key']))

        public_key_encrypted = bytes2hexstr(encrypt_symmetric(self.public_key_text, password))

        frame = Frame(
            action='public_key_response',
            payload=dict(
                public_key=public_key_encrypted,
                from_username=self.username,
                password=password_rsaed
            )
        )

        frame_response = send_frame_users(frame, self, request['from_username'])
        pprint.pprint(frame_response)
        return True

    def remove_public_key_request(self, request):
        request_path = os.path.join(self.public_key_requests_path, request['from_username'], 'request.json')
        if os.path.exists(request_path):
            os.remove(request_path)
            return True
        else:
            print("PATH NOT FOUND")
            return False

    #----------------------------------------------------------------------------------------
    #
    # public_key_response
    # public_key_responses
    #
    #-----------------------------------------------------------------------------------------
    @property
    def public_key_responses_path(self):
        return os.path.join(self.path, "public_key_responses")

    @property
    def public_key_responses(self):
        responses = []
        for d, sds, files in os.walk(self.public_key_responses_path):
            for f in files:
                if f[-5:] == '.json':
                    response_path = os.path.join(d, f)
                    with open(response_path) as f:
                        response = json.loads(f.read())
                        response.update(modified_at=datetime.datetime.fromtimestamp(os.path.getmtime(response_path)))
                        responses.append(response)

        return responses

    def store_public_key_response(self, request):
        response_path = os.path.join(
            self.public_key_responses_path,
            request['payload']['from_username']
        )

        if not os.path.exists(response_path):
            os.makedirs(response_path)

        with open(os.path.join(response_path, "response.json"), "w+") as f:
            f.write(json.dumps(request['payload']))

        return True

    def process_public_key_response(self, response):
        print(response)
        public_keys_path = os.path.join(self.public_keys_path, response['from_username'])
        if not os.path.exists(public_keys_path):
            os.makedirs(public_keys_path)

        public_key_path = os.path.join(public_keys_path, 'public.key')
        with open(public_key_path, "w+") as pkf:
            password = decrypt_rsa(
                hexstr2bytes(response['password']),
                self.private_key_text
            )
            decrypted_text = decrypt_symmetric(hexstr2bytes(response['public_key']), password)
            pkf.write(decrypted_text)

        return True

    def remove_public_key_response(self, response):
        response_path = os.path.join(self.public_key_responses_path, response['from_username'], 'response.json')
        if os.path.exists(response_path):
            os.remove(response_path)

        else:
            assert False

        return True

    #----------------------------------------------------------------------------------------
    #
    # ipcache
    #
    #-----------------------------------------------------------------------------------------
    @property
    def ipcache_path(self):
        return os.path.join(self.path, "ipcache")

    @property
    def ipcache(self):
        try:
            path = os.path.join(self.ipcache_path, "cache.json")
            return json.loads(open(path).read())
        except json.decoder.JSONDecodeError:
            return dict()
        except FileNotFoundError:
            return dict()

    def remove_contact_ip_port(self, username):
        try:
            del self.ipcache_data[username]
        except KeyError:
            pass

        path = os.path.join(self.ipcache_path, "cache.json")
        with open(path, "w+") as f:
            f.write(json.dumps(self.ipcache_data))

        return True

    def get_contact_ip_port(self, username):
        try:
            return (self.ipcache[username]['ip'], self.ipcache[username]['port'])
        except KeyError:
            return None, None

    def set_contact_ip_port(self, username, ip, port):
        self.ipcache_data[username] = dict(
            ip=ip,
            port=port
        )

        path = os.path.join(self.ipcache_path, "cache.json")
        with open(path, "w+") as f:
            f.write(json.dumps(self.ipcache_data))

        return True

    #----------------------------------------------------------------------------------------
    #
    # network topology
    # nt
    #
    #-----------------------------------------------------------------------------------------
    def hashed_ipcache(self):
        """
        prepare a version of our ipcache where the usernames and the ip:port
        are hashed... then we can pass them around without revealing much
        about the users we have contact with.
        
        this will be used in the nt call
        """
        hips = dict()

        for k in self.ipcache.keys():
            v = self.ipcache[k]
            hips[str2hashed_hexstr(k)] = str2hashed_hexstr(json.dumps(v))

        return hips

    def check_net_topo(self, custody_chain=[], hashed_ipcaches=dict()):
        custody_chain.append(str2hashed_hexstr(self.username))

        for k, v in self.hashed_ipcache().items():
            if k in hashed_ipcaches and hashed_ipcaches[k] != v:
                # TODO JHILL: poisoned
                hashed_ipcaches[k] = v
                assert False
            else:
                hashed_ipcaches[k] = v

        for k in self.ipcache.keys():
            hashed_username = str2hashed_hexstr(k)
            if hashed_username not in custody_chain:
                frame = Frame(
                    action='check_net_topo',
                    payload=dict(
                        custody_chain=custody_chain,
                        hashed_ipcaches=hashed_ipcaches
                    )
                )

                response = send_frame_users(frame, self, k)

        return True
    