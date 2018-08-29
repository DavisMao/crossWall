import socket


def main():
    addrs = socket.getaddrinfo('192.168.10.119', 8888, 0,
                               socket.SOCK_STREAM, socket.SOL_TCP)
    af, socktype, proto, canonname, sa = addrs[0]


    s = socket.socket(af, socktype, proto)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    s.connect(sa)
    #s.connect((host, port))
    #s.connect(('192.168.7.165', port))

    print(s.recv(1024).decode())

    # s.close()


if __name__ == '__main__':
    main()
