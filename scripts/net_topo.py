import os
import json
from termcolor import colored
import sys

sys.path.append("..")
from pckr_client.user import User


def main():
    users = []
    root = os.path.expanduser("~/pckr/")
    for sd in os.listdir(root):
        path = os.path.join(root, sd)
        if os.path.isdir(path):
            users.append(sd)

    for u in users:
        user = User(u)
        print("-" * 100)
        print("user {}".format(user.username))

        ipcache = json.loads(open(os.path.join(user.ipcache_path, 'cache.json')).read())
        for k, v in ipcache.items():
            public_key_text = user.get_contact_public_key(k)
            has_pk = public_key_text != None
            print(
                k, 
                colored(v['ip'], "green"), 
                colored(v['port'], "green"),
                colored("pk", "green") if has_pk else colored("no pk", "red")
            )

        print("\n")

if __name__ == '__main__':
    main()