import os
import json
import subprocess

def rpk(u1, u2):
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

    users = ['123', '234', '345', '456', '567', '678', '789', '890']

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