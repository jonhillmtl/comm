import os
import json
import subprocess
import random
from utils import aip, rpk, gather_user_ip_ports


def main():
    users = gather_user_ip_ports()
    for i in users.keys():
        for j in users.keys():
            if random.randint(0, 10) > 5:
                aip(users, i, j, robustness=11)
                rpk(i, j, robustness=11)

if __name__ == '__main__':
    main()