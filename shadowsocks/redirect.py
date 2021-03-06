import sys, socket, time, threading

LOGGING = True
loglock = threading.Lock()


# 打印日志到标准输出
def log(s, *a):
    if LOGGING:
        loglock.acquire()
        try:
            print('%s:%s' % (time.ctime(), (s % a)))
            sys.stdout.flush()
        finally:
            loglock.release()


class PipeThread(threading.Thread):
    pipes = []  # 静态成员变量，存储通讯的线程编号
    pipeslock = threading.Lock()

    def __init__(self, source, sink):
        # Thread.__init__(self) #python2.2之前版本适用
        super(PipeThread, self).__init__()
        self.source = source
        self.sink = sink
        log('Creating new pipe thread %s (%s -> %s)',
            self, source.getpeername(), sink.getpeername())
        self.pipeslock.acquire()
        try:
            self.pipes.append(self)
        finally:
            self.pipeslock.release()
        self.pipeslock.acquire()
        try:
            pipes_now = len(self.pipes)
        finally:
            self.pipeslock.release()
        log('%s pipes now active', pipes_now)

    def run(self):
        while True:
            try:
                data = self.source.recv(1024)
                if not data:
                    break
                self.sink.send(data)
            except:
                break
        log('%s terminating', self)
        self.pipeslock.acquire()
        try:
            self.pipes.remove(self)
        finally:
            self.pipeslock.release()
        self.pipeslock.acquire()
        try:
            pipes_left = len(self.pipes)
        finally:
            self.pipeslock.release()
        log('%s pipes still active', pipes_left)


class Pinhole(threading.Thread):
    def __init__(self, ori_sock, newhost, newport):
        # Thread.__init__(self) #python2.2之前版本适用
        super(Pinhole, self).__init__()
        log('Redirecting: localhost: %s->%s:%s', ori_sock, newhost, newport)
        self.newhost = newhost
        self.newport = newport
        self.sock = ori_sock
        #self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.bind(('', port))
        #self.sock.listen(5)  # 参数为timeout，单位为秒

    def run(self):
        while True:
            #newsock, address = self.sock.accept()
            #log('Creating new session for %s:%s', *address)
            fwd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            fwd.connect((self.newhost, self.newport))
            PipeThread(self.sock, fwd).start()  # 正向传送
            PipeThread(fwd, self.sock).start()  # 逆向传送
