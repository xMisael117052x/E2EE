#pragma once
#include "NetworkHelper.h"
#include "CryptoHelper.h"

class
Server {
public:
    Server() = default;
    Server(int port);

    ~Server();

    bool Start();
    void WaitForClient();
    void ReceiveEncryptedData();

private:
    int m_port;
    int m_clientSocket;
    NetworkHelper m_networkHelper;
    CryptoHelper m_cryptoHelper;
};
