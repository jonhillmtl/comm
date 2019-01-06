"""

use this script to add a new user.

adds the user and stitches it together with all users
in the local network. for testing.

usage: python scripts/bootstrap_new_user.py

"""


import subprocess
from argparse import ArgumentParser
from utils import aip, rpk, gather_user_ip_ports


def main():
    """ the main handler function for this script. """

    argparser = ArgumentParser()
    argparser.add_argument("--username", required=True)
    args = argparser.parse_args()

    subprocess.check_call([
        'pckr',
        'init_user',
        '--username={}'.format(args.username)
    ])

    users = gather_user_ip_ports()

    for i in users.keys():
        aip(users, args.username, i)

    for i in users.keys():
        rpk(args.username, i)


if __name__ == '__main__':
    main()
