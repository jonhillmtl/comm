import os
import json
import subprocess
import random

def rpk(u1, u2):
    if random.randint(0, 10) > 5:
        subprocess.check_call([
            'pckr_client',
            'rpk',
            '--username={}'.format(u1),
            '--u2={}'.format(u2)
        ])
    
        subprocess.check_call([
            'pckr_client',
            'ppk_req',
            '--username={}'.format(u2)
        ])

        subprocess.check_call([
            'pckr_client',
            'ppk_resp',
            '--username={}'.format(u1)
        ])


def aip(data, u1, u2):
    if random.randint(0, 10) > 5:
        subprocess.check_call([
            'pckr_client',
            'aip',
            '--username={}'.format(u1),
            '--u2={}'.format(u2),
            '--ip={}'.format(data[u2]['ip']),
            '--port={}'.format(data[u2]['port'])
        ])


def main():
    path = os.path.expanduser("~/pckr/surfaced.json")
    data = json.loads(open(path).read())

    users = []
    root = os.path.expanduser("~/pckr/")
    for sd in os.listdir(root):
        path = os.path.join(root, sd)
        if os.path.isdir(path):
            users.append(sd)

    for i, _ in enumerate(users):
        for j, _ in enumerate(users):
            if i != j:
                aip(data, users[i], users[j])

    for i, _ in enumerate(users):
        for j, _ in enumerate(users):
            if i != j:
                rpk(users[i], users[j])

if __name__ == '__main__':
    main()