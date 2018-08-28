import threading
import socket
import select

terminateAll = False


class ClientThread(threading.Thread):
    def __init__(self, clientSocket, targetHost, targetPort):
        threading.Thread.__init__(self)
        self.__clientSocket = clientSocket
        self.__targetHost = targetHost
        self.__targetPort = targetPort

    def run(self):
        print("Client Thread started")

        self.__clientSocket.setblocking(0)
        print(self.__targetHost)

        print(self.__targetPort)
        targetHostSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        targetHostSocket.connect((self.__targetHost, self.__targetPort))
        print("mmmmmmmmmmmmm")
        targetHostSocket.setblocking(False)

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
        print("ClienThread terminating")