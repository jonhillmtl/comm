import os
import json
import subprocess
import random
from utils import aip, rpk
from argparse import ArgumentParser

def main():
    argparser = ArgumentParser()
    argparser.add_argument("--username", required=True)
    args = argparser.parse_args()

    subprocess.check_call([
        'pckr_client',
        'init_user',
        '--username={}'.format(args.username)
    ])

    path = os.path.expanduser("~/pckr/surfaced.json")
    data = json.loads(open(path).read())

    users = []
    root = os.path.expanduser("~/pckr/")
    for sd in os.listdir(root):
        path = os.path.join(root, sd)
        if os.path.isdir(path):
            users.append(sd)

    for i, _ in enumerate(users):
        aip(data, args.username, users[i])

    for i, _ in enumerate(users):
        rpk(args.username, users[i])

if __name__ == '__main__':
    main()