"""

stitch the ips of all users to all other users.

usage: python scripts/stitch_ips.py

"""

from utils import aip, gather_user_ip_ports


def main():
    """ the main handler function for this script. """

    users = gather_user_ip_ports()

    for i in users.keys():
        for j in users.keys():
            aip(users, i, j, robustness=11)


if __name__ == '__main__':
    main()
