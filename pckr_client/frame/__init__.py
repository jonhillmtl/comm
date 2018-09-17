import uuid
import json
import binascii

class MalformedFrameError(Exception):
    pass


def split_contents(contents, split_size=512):
    splits = []
    index = 0
    while index < len(contents):
         splits.append(contents[index:index+split_size])
         index = index + split_size
    print(len(splits))
    return splits

class Frame(object):
    index = None
    count = None
    frame_id = None
    message_id = None
    mime_type = None
    content = None
    action = None

    # TODO JHILL: do this?
    # md5_hash = None

    # TODO JHILL
    def __init__(self, content, action, index=0, count=1, mime_type='text', frame_id=None, message_id=None):
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
        
        # TODO JHILL: have acceptable actions exposed
        self.action = action

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return json.dumps(self.__dict__)

    @staticmethod
    def make_frames(content, action, mime_type='text'):
        contents = split_contents(content)
        message_id = str(uuid.uuid4())
        return [Frame(content, action=action, message_id=message_id, mime_type=mime_type, index=index, count=len(contents)) for index, content in enumerate(contents)]