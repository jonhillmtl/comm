import uuid
import json
import binascii
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA 
from ..utilities import encrypt_symmetric, bytes2hexstr, split_contents

class MalformedFrameError(Exception):
    pass


class Frame(object):
    index = None
    count = None
    message_id = None
    mime_type = None
    content = None
    action = None

    # TODO JHILL: do this?
    # md5_hash = None

    # TODO JHILL: add a from_username to this for sure

    # TODO JHILL
    def __init__(
        self,
        content,
        action,
        index=0,
        count=1,
        mime_type='application/json',
        message_id=None
    ) -> None:
        self.count = count
        self.mime_type=mime_type
        self.index = index

        if message_id is None:
            message_id = str(uuid.uuid4())
        self.message_id = message_id

        assert(index < count)

        self.action = action
        self.content = content

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return json.dumps(dict(
            action=self.action,
            payload=self.content,
            message_id=self.message_id
        ))

    @staticmethod
    def make_frames(content, action, mime_type='application/json', message_id=None):
        contents = split_contents(content)

        if message_id is None:
            message_id = str(uuid.uuid4())

        return [Frame(
            content=content,
            action=action,
            message_id=message_id,
            mime_type=mime_type,
            index=index,
            count=len(contents)
        ) for index, content in enumerate(contents)]
