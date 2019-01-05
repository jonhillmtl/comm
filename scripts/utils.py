""" utilities for scripts. """

import subprocess
import random
import os

from pckr.user import User


def gather_user_ip_ports():
    """
    gather the users with their ips and ports attached.

    Returns
    -------
    dict
         a dictionary of users mapped to ip/port combos
    """

    return {User(sd).username: User(sd).current_ip_port for sd in os.listdir(os.path.expanduser("~/pckr/"))}


def rpk(user1, user2, robustness=5):
    """
    rpk - request public key.

    Parameters
    ----------
    user1: User
        the user to add request from
    user2: User
        the user to add request of
    robustness: int
        the probability that this works, set to 10 for definite

    Returns
    -------
    bool
        always True
    """

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

    return True


def aip(users, user1, user2, robustness=5):
    """
    aip - add_ipcache - add the ip of user2 to user1s ipcache.

    Parameters
    ----------
    user1: User
        the user to add to
    user2: User
        the user to add from
    robustness: int
        the probability that this works, set to 10 for definite

    Returns
    -------
    bool
        always True
    """

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

    return True
