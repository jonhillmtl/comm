"""

create a tenous network (ie: one that is loosely connected).

usage: python scripts/tenuous_network.py

"""

from utils import aip, rpk, gather_user_ip_ports


def main():
    """ the main handler function for this script. """

    users = gather_user_ip_ports()

    group1 = list(users.keys())[0:int(len(users)/2)]
    group2 = list(users.keys())[int(len(users)/2):]

    gs = [group1, group2]

    for g in gs:
        for i in g:
            for j in g:
                aip(users, i, j, robustness=11)

        for i in g:
            for j in g:
                rpk(i, j, robustness=11)

    aip(users, group1[-1], group2[0])
    aip(users, group2[0], group1[-1])

    rpk(group1[-1], group2[0])


if __name__ == '__main__':
    main()
