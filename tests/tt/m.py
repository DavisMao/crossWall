import socket


def main():
    print()
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)  # 创建 socket 对象
    host = socket.gethostname()  # 获取本地主机名
    port = 12345  # 设置端口
    s.bind((host, port))  # 绑定端口

    remotedata=""

    s.listen(5)  # 等待客户端连接
    while True:
        c, addr = s.accept()  # 建立客户端连接。

        if addr[0] == '192.168.7.165':
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #host = socket.gethostname()  # 获取本地主机名
            #port = 23456  # 设置端口
            #s1.bind((host, port))
            s1.connect((host,8888))

            remotedata=s1.recv(1024)
            c.send(remotedata)

        print('连接地址m：', addr)
        c.send('欢迎访问菜鸟教程m！'.encode())

        c.close()  # 关闭连接


if __name__ == '__main__':
    main()