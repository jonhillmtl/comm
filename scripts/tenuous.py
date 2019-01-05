from utils import aip, rpk, gather_user_ip_ports


def main():
    users = gather_user_ip_ports()

    g1 = list(users.keys())[0:int(len(users)/2)]
    g2 = list(users.keys())[int(len(users)/2):]

    gs = [g1, g2]

    for g in gs:
        for i in g:
            for j in g:
                aip(users, i, j, robustness=11)

        for i in g:
            for j in g:
                rpk(i, j, robustness=11)

    aip(users, g1[-1], g2[0])
    aip(users, g2[0], g1[-1])

    rpk(g1[-1], g2[0])


if __name__ == '__main__':
    main()
