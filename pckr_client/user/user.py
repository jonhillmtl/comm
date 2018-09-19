import os
from Crypto.PublicKey import RSA 
from ..utilities import normalize_path
import json

USER_ROOT = "~/pckr/"

class User(object):
    username = None

    def __init__(self, username):
        self.username = username

    @property
    def exists(self):
        return False

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
        responses_path = os.path.expanduser(self.path, "public_key_responses")
        for d, sds, files in os.walk(responses_path):
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

    def initiate_directory_structure(self):
        assert os.path.exists(self.path) is False
        os.makedirs(self.path)

        assert os.path.exists(self.public_key_requests_path) is False
        os.makedirs(self.public_key_requests_path)

        assert os.path.exists(self.public_key_responses_path) is False
        os.makedirs(self.public_key_responses_path)

        assert os.path.exists(self.public_keys_path) is False
        os.makedirs(self.public_keys_path)

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