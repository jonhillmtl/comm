import requests
import socket
import json
import os


def normalize_path(path):
    return os.path.normpath(os.path.abspath(os.path.expanduser(path)))


def post_json_request(endpoint, data):
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.post(endpoint, headers=headers, data=json.dumps(data))
    return response.json()


def get_user_ip_port(number):
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.get('http://127.0.0.1:5000/users/?number={}'.format(number), headers=headers).json()
    print(response)
    if 'users' in response and len(response['users']) == 1:
        return response['users'][0]['ip'], response['users'][0]['port']
    return None, None


# TODO JHILL: modify it to take the username and gather it by itself.... also to throw a top-level error
# if we can't connect... something that says they are offline and we should try again soon
# also, we should cache this... and maybe ask for the cache of everyone in our "buddy list"
# when we boot up.... if the cache goes stale we can just exit and tell the user to try again in a minute
# after we refresh the cache
def send_frame(frame, ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip.strip(), port))
    sock.send(str(frame).encode())
    return json.loads(sock.recv(4096).decode())