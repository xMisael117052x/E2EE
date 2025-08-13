#include "NetworkHelper.h"

NetworkHelper::NetworkHelper() : m_serverSocket(INVALID_SOCKET), m_initialized(false) {
  WSADATA wsaData;
  int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (result != 0) {
    std::cerr << "WSAStartup failed: " << result << '\n';
  }
  else {
    m_initialized = true;
  }
}

NetworkHelper::~NetworkHelper() {
  if (m_serverSocket != INVALID_SOCKET) {
    closesocket(m_serverSocket);
  }

  if (m_initialized) {
    WSACleanup();
  }
}

bool 
NetworkHelper::StartServer(int port) {
  // Crea el socket TCP
	m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (m_serverSocket == INVALID_SOCKET) {
    std::cerr << "Error creating socket: " << WSAGetLastError() << '\n';
    return false;
	}

  // Configura la direccion del servidor (IPv4, cualquier IP local, puerto dado)
  sockaddr_in serverAddress{};
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(static_cast<u_short>(port));
	serverAddress.sin_addr.s_addr = INADDR_ANY;

	// Asocia el socket a la direccion y puerto
  if (bind(m_serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
    std::cerr << "Error binding socket: " << WSAGetLastError() << '\n';
    closesocket(m_serverSocket);
    m_serverSocket = INVALID_SOCKET;
    return false;
	}

	// Escucha conexiones entrantes
  if (listen(m_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
    std::cerr << "Error listening on socket: " << WSAGetLastError() << '\n';
    closesocket(m_serverSocket);
    m_serverSocket = INVALID_SOCKET;
		return false;
	}

	std::cout << "Server started on port " << port << '\n';
  return true;
}

SOCKET 
NetworkHelper::AcceptClient() {
	SOCKET clientSocket = accept(m_serverSocket, nullptr, nullptr);
	if (clientSocket == INVALID_SOCKET) {
		std::cerr << "Error accepting client: " << WSAGetLastError() << '\n';
		return INVALID_SOCKET;
	}
	std::cout << "Client connected." << '\n';
  return clientSocket;
}

bool 
NetworkHelper::ConnectToServer(const std::string& ip, int port) {
  // Crea el socket TCP
	m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (m_serverSocket == INVALID_SOCKET) {
    std::cerr << "Error creating socket: " << WSAGetLastError() << '\n';
    return false;
  }
	
  // Configura la direccion del servidor (IPv4, IP dada, puerto dado)
	sockaddr_in serverAddress{};
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(static_cast<u_short>(port));
	inet_pton(AF_INET, ip.c_str(), &serverAddress.sin_addr);
	
  // Conecta al servidor
  if (connect(m_serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
    std::cerr << "Error connecting to server: " << WSAGetLastError() << '\n';
    closesocket(m_serverSocket);
    m_serverSocket = INVALID_SOCKET;
    return false;
  }
	std::cout << "Connected to server at " << ip << ":" << port << '\n';
	return true;
}

bool 
NetworkHelper::SendData(SOCKET socket, const std::string& data) {
  return send(socket, data.c_str(), static_cast<int>(data.size()), 0) != SOCKET_ERROR;
}

bool 
NetworkHelper::SendData(SOCKET socket, const std::vector<unsigned char>& data) {
  return SendAll(socket, data.data(), static_cast<int>(data.size()));
}

std::string
NetworkHelper::ReceiveData(SOCKET socket) {
	char buffer[4096] = {};
	int len = recv(socket, buffer, sizeof(buffer), 0);

  return std::string(buffer, len);
}

std::vector<unsigned char> 
NetworkHelper::ReceiveDataBinary(SOCKET socket, int size) {
  std::vector<unsigned char> buf(size);
  if (!ReceiveExact(socket, buf.data(), size)) return {};
  return buf;
}

void 
NetworkHelper::close(SOCKET socket) {
	closesocket(socket);
}

bool 
NetworkHelper::SendAll(SOCKET s, const unsigned char* data, int len) {
  int sent = 0;
  while (sent < len) {
    int n = send(s, (const char*)data + sent, len - sent, 0);
    if (n == SOCKET_ERROR) return false;
    sent += n;
  }
  return true;
}

bool 
NetworkHelper::ReceiveExact(SOCKET s, unsigned char* out, int len) {
  int recvd = 0;
  while (recvd < len) {
    int n = recv(s, (char*)out + recvd, len - recvd, 0);
    if (n <= 0) return false;
    recvd += n;
  }
  return true;
}