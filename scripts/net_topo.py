import os
import json
from termcolor import colored


def main():
    users = []
    root = os.path.expanduser("~/pckr/")
    for sd in os.listdir(root):
        path = os.path.join(root, sd)
        if os.path.isdir(path):
            users.append(sd)

    for user in users:
        print("-" * 100)
        print("user {}".format(user))

        ipcache = json.loads(open(os.path.join(root, user, 'ipcache', 'cache.json')).read())
        for k, v in ipcache.items():
            print(k, colored(v['ip'], "green"), colored(v['port'], "green"))

        print("\n")

if __name__ == '__main__':
    main()