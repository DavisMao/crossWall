import socket
import select
import threading

BUF_SIZE = 32 * 1024



class ClientThread(threading.Thread):
#class ClientThread():
    def __init__(self, clientSocket, targetHost, targetPort):
        threading.Thread.__init__(self)
        self.__clientSocket = clientSocket
        self.__targetHost = targetHost
        self.__targetPort = targetPort

    def run(self):
    #def do(self):
        print("Client Thread started")

        print(self.__clientSocket.getsockname()[0])
        print()
        self.__clientSocket.setblocking(0)
        print(self.__targetHost)

        print(self.__targetPort)
        targetHostSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        targetHostSocket.connect((self.__targetHost, self.__targetPort))

        targetHostSocket.setblocking(False)


        clientData = ""
        targetHostData = ""
        terminate = False
        while not terminate:
            inputs = [self.__clientSocket, targetHostSocket]
            outputs = []

            if len(clientData) > 0:
                outputs.append(self.__clientSocket)

            if len(targetHostData) > 0:
                outputs.append(targetHostSocket)

            try:

                inputsReady, outputsReady, errorsReady = select.select(inputs, outputs, [], 1.0)

            except Exception as e:
                print("error here")
                print(e)
                break

            for inp in inputsReady:
                if inp == self.__clientSocket:
                    try:
                        data = self.__clientSocket.recv(BUF_SIZE)

                        if data != None:
                            if len(data) > 0:

                                #nTmp = data.decode()
                                #targetHostData += nTmp
                                targetHostData += data
                            else:
                                terminate = True
                    except Exception as e:
                        print("my fault")
                        print(e)
                elif inp == targetHostSocket:
                    try:
                        data = targetHostSocket.recv(BUF_SIZE)

                        if data != None:
                            if len(data) > 0:
                                #nTmp = data.decode()
                                #clientData += nTmp
                                clientData += data
                            else:
                                terminate = True
                    except Exception as e:
                        print("XXXXXXX")
                        print(e)

            for out in outputsReady:
                if out == self.__clientSocket and len(clientData) > 0:
                    #bytesWritten = self.__clientSocket.send(clientData.encode())
                    bytesWritten = self.__clientSocket.send(clientData)
                    if bytesWritten > 0:
                        clientData = clientData[bytesWritten:]
                elif out == targetHostSocket and len(targetHostData) > 0:
                    #bytesWritten = targetHostSocket.send(targetHostData.encode())
                    #import pdb
                    #pdb.set_trace()
                    bytesWritten = targetHostSocket.send(targetHostData)
                    if bytesWritten > 0:
                        targetHostData = targetHostData[bytesWritten:]

        self.__clientSocket.close()
        targetHostSocket.close()
        print("ClienThread terminating")