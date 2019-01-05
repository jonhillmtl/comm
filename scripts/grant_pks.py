from utils import rpk, gather_user_ip_ports


def main():
    users = gather_user_ip_ports()

    for i in users.keys():
        for j in users.keys():
            rpk(i, j, robustness=11)


if __name__ == '__main__':
    main()
