import json
import uuid
import time

from ..utilities import command_header, send_frame_users, normalize_path, split_contents, is_binary
from ..utilities import encrypt_rsa, encrypt_symmetric, decrypt_symmetric, decrypt_rsa
from ..utilities import hexstr2bytes, bytes2hexstr, str2hashed_hexstr
from ..frame import Frame

class Message(object):
    user = None
    u2 = None
    filename = None
    mime_type = None
    message_id = None
    password = None

    def __init__(self, user, filename, mime_type, u2):
        self.user = user
        self.u2 = u2
        self.filename = filename
        self.mime_type = mime_type
        self.message_id = str(uuid.uuid4())
        self.password = str(uuid.uuid4())
        
    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def _send_key(self):
        public_key_text = self.user.get_contact_public_key(self.u2)
        if public_key_text is None:
            print(colored("public_key for {} not found, can't send message".format(self.u2), "red"))
            return False
 
        key = dict(
            password=self.password,
            message_id=self.message_id,
            md5='',
            length=1000,
            filename=self.filename
        )

        password = str(uuid.uuid4())
        password_encrypted = bytes2hexstr(encrypt_rsa(
            password,
            public_key_text
        ))

        key_encrypted = bytes2hexstr(encrypt_symmetric(
            json.dumps(key),
            password
        ))

        payload = dict(
            key=key_encrypted,
            password=password_encrypted
        )

        key_frame = Frame(
            action='send_message_key',
            payload=payload
        )
        response = send_frame_users(key_frame, self.user, self.u2)
        print("send_message_key", response)

        return True

    def _send_message(self):
        public_key_text = self.user.get_contact_public_key(self.u2)
        if public_key_text is None:
            print(colored("public_key for {} not found, can't send message".format(self.u2), "red"))
            return False
 
        meta = dict(
            message_id=self.message_id,
            filename=self.filename
        )

        password = str(uuid.uuid4())
        password_encrypted = bytes2hexstr(encrypt_rsa(
            password,
            public_key_text
        ))

        meta_encrypted = bytes2hexstr(encrypt_symmetric(
            json.dumps(meta),
            password
        ))

        if is_binary(self.mime_type):
            content = open(self.filename, "rb").read()
        else:
            content = open(self.filename, "r").read()

        tt = time.time()
        et = time.time()
        encrypted_content = bytes2hexstr(encrypt_symmetric(
            content,
            self.password
        ))
        print("encryption time", time.time() - et)

        content_splits = split_contents(encrypted_content)
        for index, content_split in enumerate(content_splits):
            ft = time.time()
            frame = Frame(
                action='send_message',
                payload=dict(
                    password=password_encrypted,
                    content=content_split,
                    meta=meta_encrypted
                )
            )

            response = send_frame_users(frame, self.user, self.u2)
            print("send_message", index, response, time.time() - ft)

        print("total time", time.time() - tt)
        return True

    def _send_message_term(self):
        public_key_text = self.user.get_contact_public_key(self.u2)
        if public_key_text is None:
            print(colored("public_key for {} not found, can't send message".format(self.u2), "red"))
            return False
 
        term = dict(
            message_id=self.message_id,
            filename=self.filename,
            mime_type=self.mime_type
        )

        password = str(uuid.uuid4())
        password_encrypted = bytes2hexstr(encrypt_rsa(
            password,
            public_key_text
        ))

        term_encrypted = bytes2hexstr(encrypt_symmetric(
            json.dumps(term),
            password
        ))

        payload = dict(
            term=term_encrypted,
            password=password_encrypted
        )

        term_frame = Frame(
            action='send_message_term',
            payload=payload
        )

        response = send_frame_users(term_frame, self.user, self.u2)
        print("send_frame_term", response)

        return True

    def send(self):
        self._send_key()
        self._send_message()
        self._send_message_term()
        return True
