import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from ..utilities import normalize_path, decrypt_symmetric, hexstr2bytes, bytes2hexstr, encrypt_symmetric, str2hashed_hexstr, send_frame
import json
import binascii
import uuid
from ..ipcache import IPCache
from ..frame import Frame

USER_ROOT = "~/pckr/"

class User(object):
    username = None

    def __init__(self, username):
        self.username = username

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
    def public_key_requests_path(self):
        return os.path.join(self.path, "public_key_requests")

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
                        responses.append(json.loads(f.read()))
        return responses

    @property
    def public_key_requests(self):
        requests = []
        print(self.public_key_requests_path)
        for d, sds, files in os.walk(self.public_key_requests_path):
            for f in files:
                if f[-5:] == '.json':
                    request_path = os.path.join(d, f)
                    with open(request_path) as f:
                        requests.append(json.loads(f.read()))
        return requests

    @property
    def private_rsakey(self):
        # TODO JHILL: error handling! bad one...
        with open(self.private_key_path) as f:
            return PKCS1_OAEP.new(RSA.importKey(f.read()))

        return None
    
    @property
    def messages_path(self):
        return os.path.join(self.path, "messages")

    @property
    def message_keys_path(self):
        return os.path.join(self.path, "message_keys")

    @property
    def ipcache_path(self):
        return os.path.join(self.path, "ipcache")

    @property
    def seek_tokens_path(self):
        return os.path.join(self.path, "seek_tokens")

    def seek_user(self, u2):
        public_key_text = self.get_contact_public_key(u2)
        if public_key_text is None:
            print(colored("public_key for {} not found, can't seek_user".format(u2), "red"))
            sys.exit(1)

        path = os.path.join(self.path, "current_ip_port.json")
        with open(path, "r") as f:
            current_ip_port = json.loads(open(path).read())

        seek_token = str(uuid.uuid4())
        seek_token_path = os.path.join(self.seek_tokens_path, "{}.json".format(u2))
        with open(seek_token_path, "w+") as f:
            f.write(json.dumps(
                dict(seek_token=seek_token)
            ))
        print(seek_token_path)

        # TODO JHILL: attach our IP, port, and public_key
        # TODO JHILL: encrypt a password using their public_key
        # TODO JHILL: encrypt our credentials using that password
        host_info = dict(
            ip=current_ip_port['ip'],
            port=current_ip_port['port'],
            public_key=self.public_key_text,
            from_username=self.username,
            seek_token=seek_token
        )
        print(host_info)

        password = str(uuid.uuid4())
        rsa_key = RSA.importKey(public_key_text)
        rsa_key = PKCS1_OAEP.new(rsa_key)
        password_encrypted = rsa_key.encrypt(password.encode())
        password_encrypted = bytes2hexstr(password_encrypted)

        encrypted_host_info = bytes2hexstr(encrypt_symmetric(
            json.dumps(host_info).encode(),
            password.encode()
        ))

        # send the message out to everyone we know
        ipcache = IPCache(self)
        for k, v in ipcache.data.items():
            ip, port = v['ip'], v['port']

            frame = Frame(content=dict(
                host_info=encrypted_host_info,
                password=password_encrypted,
                custody_chain=[str2hashed_hexstr(self.username)]
            ), action='seek_user')

            response = send_frame(frame, ip, port)
            print(response)

    def get_contact_public_key(self, contact):
        try:
            path = os.path.join(self.public_keys_path, contact, "public.key")
            return open(path).read()
        except FileNotFoundError as e:
            return None

    def initiate_directory_structure(self):
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

    def initiate_rsa(self):
        new_key = RSA.generate(2048, e=65537) 
        with open(self.public_key_path, "wb") as f:
            f.write(new_key.publickey().exportKey("PEM") )

        with open(self.private_key_path, "wb") as f:
            f.write(new_key.exportKey("PEM"))

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
            private_rsakey = self.private_rsakey
            password = private_rsakey.decrypt(hexstr2bytes(response['password']))
            decrypted_text = decrypt_symmetric(hexstr2bytes(response['public_key']), password)
            pkf.write(decrypted_text)
