import threading
import socket
import json
import os
import binascii
from termcolor import colored
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from Crypto.Cipher import Blowfish

class SocketThread(threading.Thread):
    clientsocket = None
    phone_number = None

    def __init__(self, clientsocket, phone_number):
        super(SocketThread, self).__init__()
        self.clientsocket = clientsocket
        self.phone_number = phone_number
    
    def get_public_key(self):
        pass

    def _attempt_stitch_files(self, request):
        # print(request)
        path = os.path.expanduser("~/pckr/received/")
        path = os.path.join(path, request['message_id'])
        for d, sds, files in os.walk(path):
            print("files:", len(files))
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


    def _receive_send_file(self, request):
        key_path = os.path.expanduser(os.path.join("~/pckr/", self.phone_number, "transmit_key", request['message_id'], "key.json"))
        key_data = json.loads(open(key_path).read())
        c1  = Blowfish.new(key_data['encryption_key'].encode(), Blowfish.MODE_ECB)
        decrypted_text = c1.decrypt(binascii.unhexlify(request['payload']))


        decrypted_text = decrypted_text.replace(b'\r', b'')
        decrypted_text = decrypted_text.replace(b'\x04', b'')
        decrypted_text = decrypted_text.replace(b'\x0b', b'')
        decrypted_text = decrypted_text.replace(b'\x0c', b'')
        decrypted_text = decrypted_text.replace(b'\x0f', b'')
        decrypted_text = decrypted_text.replace(b'\x0e', b'')
        decrypted_text = decrypted_text.replace(b'\x02', b'')
        payload = json.loads(decrypted_text.decode())

        filename = "{}_{}_{}".format(
            payload['frame_id'],
            payload['index'],
            payload['count']
        )
        path = os.path.expanduser(os.path.join("~/pckr/received/", request['message_id']))
        if not os.path.exists(path):
            os.makedirs(path)
        path = os.path.join(path, filename)

        # TODO JHILL: obviously split the handling on binary or not, mime_types!
        # and yeah this would be as good a time as any to introduce 
        if payload['mime_type'] == 'image/png':
            with open(path, "wb+") as f:
                f.write(binascii.unhexlify(payload['content']))
        else:
            with open(path, "w+") as f:
                f.write(payload['content'])

        self._attempt_stitch_files(payload)

        return json.dumps(dict(
            success=True,
            filename=path
        )).encode()

    def _receive_send_file_transmit_key(self, request):
        private_key_path = os.path.expanduser(os.path.join("~/pckr/", self.phone_number, "private.key"))
        private_key_text = open(private_key_path).read()

        rsakey = RSA.importKey(private_key_text)
        rsakey = PKCS1_OAEP.new(rsakey)
        payload = json.loads(rsakey.decrypt(binascii.unhexlify(request['payload'])))

        key_path = os.path.expanduser(os.path.join("~/pckr/", self.phone_number, "transmit_key", request['message_id']))
        if not os.path.exists(key_path):
            os.makedirs(key_path)

        with open(os.path.join(key_path, "key.json"), "w+") as f:
            f.write(json.dumps(payload['content']))

        return json.dumps(dict(
            success=True,
            message_id=request['message_id']
        )).encode()

    def process_request(self, request_text):
        print(len(request_text))
        # print(request_text)
        try:
            request_data = json.loads(request_text)

            # TODO JHILL: error handler!!!
            if request_data['action'] == 'ping':
                return json.dumps(dict(
                    success=True,
                    message="pong"
                )).encode()
            elif request_data['action'] == 'send_file':
                print("*"*100)
                return self._receive_send_file(request_data)
            elif request_data['action'] == 'send_file_transmit_key':
                return self._receive_send_file_transmit_key(request_data)
            else:
                return json.dumps(dict(
                    success=False,
                    error="unknown action '{}'".format(request_data['action'])
                )).encode()
        except json.decoder.JSONDecodeError as e:
            print("!"*100)
            print(e)
            print(request_text)

        return b"{}"


    def run(self):
        request_text = self.clientsocket.recv(32368*2).decode()

        response = self.process_request(request_text)

        self.clientsocket.sendall(response)
        self.clientsocket.close()


class Broadcaster(threading.Thread):
    login_token = None
    serversocket = None
    hostname = None
    phone_number = None

    def __init__(self, phone_number, port):
        super(Broadcaster, self).__init__()
        self.port = port
        self.phone_number = phone_number

        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serversocket.bind((socket.gethostname(), self.port))
        self.serversocket.listen(5)

        self.hostname = socket.gethostname()

    def run(self):
        while True:
            try:
                # print("*" * 100)
                (clientsocket, address) = self.serversocket.accept()
                st = SocketThread(clientsocket, self.phone_number)
                st.start()
            except ConnectionAbortedError:
                pass