"""

use this script to damage the ip cache of all local users.

usage: python scripts/damage_ip_cache.py

"""

import random
import subprocess
from utils import gather_user_ip_ports


def main():
    """ the main handler function for this script. """

    users = gather_user_ip_ports()

    for i in users.keys():
        for j in users.keys():
            if random.randint(0, 10) < 3:
                subprocess.check_call([
                    'pckr',
                    'rip',
                    '--username={}'.format(i),
                    '--user2={}'.format(j)
                ])


if __name__ == '__main__':
    main()
