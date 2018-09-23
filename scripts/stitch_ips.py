import os
import json
import subprocess
import random
from utils import aip, rpk


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
                aip(data, users[i], users[j], robustness=11)

if __name__ == '__main__':
    main()