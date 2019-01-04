import subprocess
import random
import os
import sys

sys.path.append("..")
from pckr.user import User


def gather_user_ip_ports():
    return {User(sd).username : User(sd).current_ip_port for sd in os.listdir(os.path.expanduser("~/pckr/"))}

def rpk(u1, u2, robustness=5):
    if u1 == u2:
        return

    if random.randint(0, 10) < robustness:
        subprocess.check_call([
            'pckr',
            'rpk',
            '--username={}'.format(u1),
            '--u2={}'.format(u2)
        ])
    
        subprocess.check_call([
            'pckr',
            'ppk_req',
            '--username={}'.format(u2)
        ])

        subprocess.check_call([
            'pckr',
            'ppk_resp',
            '--username={}'.format(u1)
        ])


def aip(users, u1, u2, robustness=5):
    if u1 == u2:
        return

    if random.randint(0, 10) < robustness:
        subprocess.check_call([
            'pckr',
            'aip',
            '--username={}'.format(u1),
            '--u2={}'.format(u2),
            '--ip={}'.format(users[u2]['ip']),
            '--port={}'.format(users[u2]['port'])
        ])
