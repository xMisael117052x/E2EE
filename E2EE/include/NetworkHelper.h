#pragma once
#include "Prerequisites.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

class
    NetworkHelper {
public:
    NetworkHelper();
    ~NetworkHelper();

    // Modo serrver
    bool
    ServerMode(int port);

    bool
    StartSever(int port);

    SOCKET
    AcceptClient();

    // Modo cliente
    bool
    ConnectToServer(const std::string& ip, int port);

    // Enviar y recibir datos
    bool
    SendData(SOCKET socket, const std::string& data);

    bool
    SendData(SOCKET socket, const std::vector<unsigned char>& data);

    std::string
    ReceiveData(SOCKET socket);

    std::vector<unsigned char>
    ReceiveData(SOCKET socket, int size = 0);

    void
    close(SOCKET socket);

private:
    SOCKET m_serverSocket = -1;
    bool m_initialized;
};
