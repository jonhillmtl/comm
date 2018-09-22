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

    for u in sorted(users):
        user = User(u)
        print(colored("*" * 100, "blue"))
        print("user {}".format(user.username))

        path = os.path.join(user.ipcache_path, 'cache.json')
        if os.path.exists(path):
            ipcache = json.loads(open(path).read())
            if len(ipcache.keys()):
                print("\nipcache")
                for k in sorted(ipcache.keys()):
                    v = ipcache[k]
                    public_key_text = user.get_contact_public_key(k)
                    has_pk = public_key_text != None
                    print(
                        k, 
                        colored(v['ip'], "green"), 
                        colored(v['port'], "green"),
                        colored("pk", "green") if has_pk else colored("no pk", "red")
                    )

                if len(user.public_key_requests):
                    print("\npublic_key_requests")
                    for ppk_req in user.public_key_requests:
                        print(ppk_req['from_username'], ppk_req['modified_at'])

        if len(user.public_key_responses):
            print("\npublic_key_responses")
            for ppk_req in user.public_key_responses:
                print(ppk_req['from_username'], ppk_req['modified_at'])

        print(colored("*" * 100, "blue"))
        print("\n")

if __name__ == '__main__':
    main()