import uuid
import json
import binascii
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA 
from Crypto.Cipher import Blowfish

class MalformedFrameError(Exception):
    pass

# TODO JHILL: put in utility file
# TODO JHILL: could be one-liner somehow, or use itertools
def split_contents(contents, split_size=4096):
    splits = []
    index = 0
    while index < len(contents):
         splits.append(contents[index:index+split_size])
         index = index + split_size
    return splits

BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS),encoding='utf8')

class Frame(object):
    index = None
    count = None
    frame_id = None
    message_id = None
    mime_type = None
    content = None
    action = None
    encryption_type = None
    encryption_key = None

    # TODO JHILL: do this?
    # md5_hash = None

    # TODO JHILL
    def __init__(
        self,
        content,
        action,
        encryption_type,
        encryption_key,
        index=0,
        count=1,
        mime_type='text',
        frame_id=None,
        message_id=None
    ):
        self.count = count
        self.mime_type=mime_type
        self.index = index

        if frame_id is None:
            frame_id = str(uuid.uuid4())
        self.frame_id = frame_id

        if message_id is None:
            message_id = str(uuid.uuid4())
        self.message_id = message_id

        assert(index < count)

        if mime_type == 'image/png':
            self.content = binascii.hexlify(content).decode()
        else:
            self.content = content
        # TODO JHILL: encrypt

        # TODO JHILL: have acceptable actions exposed
        self.action = action
        self.encryption_type = encryption_type
        self.encryption_key = encryption_key

    def __unicode__(self):
        return str(self)

    def __str__(self):
        if self.encryption_type == 'symmetric_key':
            cipher = Blowfish.new(self.encryption_key.encode(), Blowfish.MODE_ECB)
            payload = self.__dict__
            payload_content = cipher.encrypt(pad(json.dumps(payload)))
        elif self.encryption_type == 'public_key':
            rsa_key = RSA.importKey(self.encryption_key)
            rsa_key = PKCS1_OAEP.new(rsa_key)
            payload = dict(
                content=self.content
            )

            payload_content = rsa_key.encrypt(json.dumps(payload).encode())
        else:
            raise MalformedFrameError()

        payload_content = binascii.hexlify(payload_content).decode()

        return json.dumps(dict(
            action=self.action,
            payload=payload_content,
            message_id=self.message_id
        ))

    @staticmethod
    def make_frames(content, action, encryption_type, encryption_key, mime_type='text', message_id=None):
        contents = split_contents(content)
        if message_id is None:
            message_id = str(uuid.uuid4())
        return [Frame(
            content=content,
            action=action,
            encryption_type=encryption_type,
            encryption_key=encryption_key,
            message_id=message_id,
            mime_type=mime_type,
            index=index, count=len(contents)
        ) for index, content in enumerate(contents)]