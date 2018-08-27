import socket


def getNextHop():
    return '192.168.10.181'


def main():
    print()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 8888
    s.bind((host, port))

    remotedata = ""

    s.listen(1024)
    while True:
        c, addr = s.accept()

        nexthop = getNextHop()
        if nexthop != '' and nexthop == '192.168.10.181':
            # if addr[0] == '192.168.10.181':
            # nexthop = '192.168.10.181'
            addr1 = socket.getaddrinfo(nexthop, 8888, 0,
                                       socket.SOCK_STREAM, socket.SOL_TCP)
            af1, socktype1, proto1, canonname1, sa1 = addr1[0]

            s1 = socket.socket(af1, socktype1, proto1)
            s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s1.connect(sa1)

            remotedata = s1.recv(1024)
            c.send(remotedata)
        else:
            print('connect address-s', addr)
            c.send('welcome-s'.encode())

        c.close()


if __name__ == '__main__':
    main()
