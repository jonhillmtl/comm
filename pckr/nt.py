from .user import User

from termcolor import colored
import json
import os


def _users():
    users = []
    root = os.path.expanduser("~/pckr/")
    for sd in os.listdir(root):
        path = os.path.join(root, sd)
        if os.path.isdir(path):
            users.append(sd)
    return sorted(users)


def analyze_topo():
    cached_ips = dict()
    for u in _users():
        user = User(u)

        path = os.path.join(user.ipcache_path, 'cache.json')
        if os.path.exists(path):
            ipcache = json.loads(open(path).read())
            for k in sorted(ipcache.keys()):
                v = ipcache[k]

                ip_port = "{}:{}".format(v['ip'], v['port'])

                if k not in cached_ips:
                    cached_ips[k] = {
                        ip_port: [user.username]
                    }
                else:
                    if ip_port in cached_ips[k]:
                        cached_ips[k][ip_port].append(user.username)
                    else:
                        cached_ips[k][ip_port] = [user.username]

    import pprint
    pprint.pprint(cached_ips)
    consistent = True
    for username, cached_ip in cached_ips.items():
        if len(set(cached_ip)) > 1:
            print(colored("network topology damaged: user {} has more than 1 ip:port: {}".format(
                username,
                cached_ip
            )))
            consistent = False
    
    if consistent:
        print(colored("network topology is consistent", "green"))
    print("\n")

def dump_topo():
    for u in _users():
        user = User(u)
        print(colored("*" * 100, "blue"))
        print("user {}".format(user.username))

        path = os.path.join(user.ipcache_path, 'cache.json')
        if os.path.exists(path):
            ipcache = json.loads(open(path).read())
            if len(ipcache.keys()):
                print("\n")
                for k in sorted(ipcache.keys()):
                    u2 = User(k)

                    v = ipcache[k]
                    user_has_u2_pk = user.get_contact_public_key(k) != None
                    u2_has_user_pk = u2.get_contact_public_key(user.username) != None
            
                    print( 
                        k,
                        colored(v['ip'], "green"), 
                        colored(v['port'], "green"),
                        colored("(pk)", "green") if user_has_u2_pk else colored("(no pk)", "red"),
                        colored("(has {} pk)".format(user.username), "green") if u2_has_user_pk else colored("(does not have {} pk)".format(user.username), "red")
                    )

                if len(user.public_key_requests):
                    print("\npublic_key_requests")
                    for ppk_req in user.public_key_requests:
                        print(ppk_req['u2'], ppk_req['modified_at'])

        if len(user.public_key_responses):
            print("\npublic_key_responses")
            for ppk_req in user.public_key_responses:
                print(ppk_req['u2'], ppk_req['modified_at'])

        print(colored("*" * 100, "blue"))
        print("\n")


def main():
    dump_topo()
    analyze_topo()
