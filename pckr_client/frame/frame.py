from ..utilities import encrypt_symmetric, bytes2hexstr

import binascii
import json
import uuid


class MalformedFrameError(Exception):
    pass


class Frame(object):
    frame_id = None
    payload = None
    action = None

    # TODO JHILL
    def __init__(
        self,
        payload,
        action,
        frame_id=None
    ) -> None:
        if frame_id is None:
            frame_id = str(uuid.uuid4())
        self.frame_id = frame_id
        self.action = action
        self.payload = payload

        assert type(payload) == dict

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return json.dumps(dict(
            action=self.action,
            payload=self.payload,
            frame_id=self.frame_id,
        ))        