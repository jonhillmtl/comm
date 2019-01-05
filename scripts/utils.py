import subprocess
import random
import os

from pckr.user import User


def gather_user_ip_ports():
    return {User(sd).username: User(sd).current_ip_port for sd in os.listdir(os.path.expanduser("~/pckr/"))}


def rpk(user1, user2, robustness=5):
    if user1 == user2:
        return

    if random.randint(0, 10) < robustness:
        subprocess.check_call([
            'pckr',
            'rpk',
            '--username={}'.format(user1),
            '--user2={}'.format(user2)
        ])

        subprocess.check_call([
            'pckr',
            'ppk_req',
            '--username={}'.format(user2)
        ])

        subprocess.check_call([
            'pckr',
            'ppk_resp',
            '--username={}'.format(user1)
        ])


def aip(users, user1, user2, robustness=5):
    if user1 == user2:
        return

    if random.randint(0, 10) < robustness:
        subprocess.check_call([
            'pckr',
            'aip',
            '--username={}'.format(user1),
            '--user2={}'.format(user2),
            '--ip={}'.format(users[user2]['ip']),
            '--port={}'.format(users[user2]['port'])
        ])
