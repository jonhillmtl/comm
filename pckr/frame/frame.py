import json
import uuid


class Frame:
    frame_id = None
    payload = None
    action = None

    def __init__(
        self,
        payload: dict,
        action: str
    ) -> None:
        self.frame_id = str(uuid.uuid4())
        self.action = action
        self.payload = payload

    def __unicode__(self) -> str:
        return str(self)

    def __str__(self) -> str:
        return json.dumps(self.__dict__)
