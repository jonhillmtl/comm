import random
import subprocess
from utils import gather_user_ip_ports


def main():
    users = gather_user_ip_ports()

    for i in users.keys():
        for j in users.keys():
            if random.randint(0, 10) < 3:
                subprocess.check_call([
                    'pckr',
                    'rip',
                    '--username={}'.format(i),
                    '--u2={}'.format(j)
                ])


if __name__ == '__main__':
    main()
