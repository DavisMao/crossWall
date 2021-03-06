import socket
import threading
import select
import sys

terminateAll = False


class ClientThread(threading.Thread):
    def __init__(self, clientSocket, targetHost, targetPort):
        threading.Thread.__init__(self)
        self.__clientSocket = clientSocket
        self.__targetHost = targetHost
        self.__targetPort = targetPort

    def run(self):
        print
        "Client Thread started"

        self.__clientSocket.setblocking(0)

        targetHostSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #targetHostSocket.connect((self.__targetHost, self.__targetPort))
        targetHostSocket.connect((socket.gethostname(), self.__targetPort))
        targetHostSocket.setblocking(0)

        clientData = ""
        targetHostData = ""
        terminate = False
        while not terminate and not terminateAll:
            inputs = [self.__clientSocket, targetHostSocket]
            outputs = []

            if len(clientData) > 0:
                outputs.append(self.__clientSocket)

            if len(targetHostData) > 0:
                outputs.append(targetHostSocket)

            try:
                inputsReady, outputsReady, errorsReady = select.select(inputs, outputs, [], 1.0)
            except Exception as e:
                print(e)
                break

            for inp in inputsReady:
                if inp == self.__clientSocket:
                    try:
                        data = self.__clientSocket.recv(4096)
                    except Exception as e:
                        print(e)

                    if data != None:
                        if len(data) > 0:
                            nTmp = data.decode()
                            targetHostData += nTmp
                        else:
                            terminate = True
                elif inp == targetHostSocket:
                    try:
                        data = targetHostSocket.recv(4096)
                    except Exception as e:
                        print(e)

                    if data != None:
                        if len(data) > 0:
                            nTmp = data.decode()
                            clientData += nTmp
                        else:
                            terminate = True

            for out in outputsReady:
                if out == self.__clientSocket and len(clientData) > 0:
                    bytesWritten = self.__clientSocket.send(clientData.encode())
                    if bytesWritten > 0:
                        clientData = clientData[bytesWritten:]
                elif out == targetHostSocket and len(targetHostData) > 0:
                    bytesWritten = targetHostSocket.send(targetHostData.encode())
                    if bytesWritten > 0:
                        targetHostData = targetHostData[bytesWritten:]

        self.__clientSocket.close()
        targetHostSocket.close()
        print
        "ClienThread terminating"


if __name__ == '__main__':


    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    localHost = socket.gethostname()
    localPort = 12345
    targetHost = '192.168.7.163'
    targetPort = 8888

    serverSocket.bind((localHost, localPort))
    serverSocket.listen(5)
    print
    "Waiting for client..."
    while True:
        try:
            clientSocket, address = serverSocket.accept()
        except KeyboardInterrupt:
            print
            "\nTerminating..."
            terminateAll = True
            break
        a,b = clientSocket.getsockname()
        addrs = socket.getaddrinfo(a, b, 0,
                                   socket.SOCK_STREAM, socket.SOL_TCP)
        ClientThread(clientSocket, targetHost, targetPort).start()

    #serverSocket.close()