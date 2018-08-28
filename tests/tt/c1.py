import socket


def main():
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)  # 创建 socket 对象
    host = socket.gethostname()  # 获取本地主机名
    port = 12345  # 设置端口好

    s.connect((host, port))
    print(s.recv(1024).decode())
    s.close()

if __name__ == '__main__':
    main()