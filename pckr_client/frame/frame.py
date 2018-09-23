import json
import uuid


class Frame(object):
    frame_id = None
    payload = None
    action = None

    def __init__(
        self,
        payload,
        action
    ) -> None:
        self.frame_id = str(uuid.uuid4())
        self.action = action
        self.payload = payload

        assert type(payload) == dict

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return json.dumps(self.__dict__)