import threading
import socket
import json
import os
import binascii


class SocketThread(threading.Thread):
    clientsocket = None

    def __init__(self, clientsocket):
        super(SocketThread, self).__init__()
        self.clientsocket = clientsocket
    
    def get_public_key(self):
        pass

    def _attempt_stitch_files(self, request):
        path = os.path.expanduser("~/comm/received/")
        path = os.path.join(path, request['message_id'])
        for d, sds, files in os.walk(path):
            if len(files) == request['count']:
                indexed = dict()
                for file in files:
                    index = int(file.split('_')[1])
                    print(index)
                    indexed[index] = file
                    
                content = b''
                for i in range(0, request['count']):
                    file_path = os.path.join(path, indexed[i])
                    with open(file_path, 'rb') as f:
                        content = content + f.read()
                output_path = os.path.join(path, "out.png")
                with open(output_path, "wb+") as f:
                    f.write(content)
                print(output_path)


    # TODO JHILL: obviously split the handling on binary or not, mime_types!
    # and yeah this would be as good a time as any to introduce 

    def _receive_send_file(self, request):
        path = os.path.expanduser("~/comm/received/")
        if not os.path.exists(path):
            os.makedirs(path)
        path = os.path.join(path, request['message_id'])
        if not os.path.exists(path):
            os.makedirs(path)

        filename = "{}_{}_{}".format(
            request['frame_id'],
            request['index'],
            request['count']
        )
        # print(filename)
        path = os.path.join(path, filename)

        if request['mime_type'] == 'image/png':
            with open(path, "wb+") as f:
                f.write(binascii.unhexlify(request['content']))
        else:
            with open(path, "w+") as f:
                f.write(request['content'])

        self._attempt_stitch_files(request)

        return json.dumps(dict(
            success=True,
            filename=path
        )).encode()

    def process_request(self, request_text):
        # print(request_text)
        request_data = json.loads(request_text)

        # TODO JHILL: error handler!!!
        if request_data['action'] == 'ping':
            return json.dumps(dict(
                success=True,
                message="pong"
            )).encode()
        elif request_data['action'] == 'send_file':
            return self._receive_send_file(request_data)
        else:
            return json.dumps(dict(
                success=False,
                error="unknown action '{}'".format(request_data['action'])
            )).encode()

        return "{}"


    def run(self):
        request_text = self.clientsocket.recv(8092).decode()

        response = self.process_request(request_text)

        self.clientsocket.sendall(response)
        self.clientsocket.close()


class Broadcaster(threading.Thread):
    login_token = None
    serversocket = None
    hostname = None

    def __init__(self, port):
        super(Broadcaster, self).__init__()
        self.port = port

        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serversocket.bind((socket.gethostname(), self.port))
        self.serversocket.listen(5)

        self.hostname = socket.gethostname()

    def run(self):
        while True:
            try:
                # print("*" * 100)
                (clientsocket, address) = self.serversocket.accept()
                st = SocketThread(clientsocket)
                st.start()
            except ConnectionAbortedError:
                pass