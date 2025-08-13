#include "Client.h"
#include "CryptoHelper.h"
#include <cstring>

#include <thread>

Client::Client(const std::string& ip, int port)
	: m_ip(ip), m_port(port), m_serverSock(INVALID_SOCKET) {
	// Genera par de claves RSA al instanciar
	m_crypto.GenerateRSAKeys();
	// Genera la clave AES que se usara para cifrar mensajes
	m_crypto.GenerateAESKey();
}

Client::~Client() {
	if (m_serverSock != INVALID_SOCKET) {
		m_net.close(m_serverSock);
	}
}

bool 
Client::Connect() {
	std::cout << "[Client] Conectando al servidor " << m_ip << ":" << m_port << "...\n";
	bool connected = m_net.ConnectToServer(m_ip, m_port);
	if (connected) {
		m_serverSock = m_net.m_serverSocket; // Guardar el socket una vez conectado
		std::cout << "[Client] Conexion establecida.\n";
	}
	else {
		std::cerr << "[Client] Error al conectar.\n";
	}
	return connected;
}

void
Client::ExchangeKeys() {
	// 1. Recibe la clave publica del servidor
	std::string serverPubKey = m_net.ReceiveData(m_serverSock);
	m_crypto.LoadPeerPublicKey(serverPubKey);
	std::cout << "[Client] Clave publica del servidor recibida.\n";

	// 2. Envia la clave publica del cliente
	std::string clientPubKey = m_crypto.GetPublicKeyString();
	m_net.SendData(m_serverSock, clientPubKey);
	std::cout << "[Client] Clave publica del cliente enviada.\n";
}

void 
Client::SendAESKeyEncrypted() {
	std::vector<unsigned char> encryptedAES = m_crypto.EncryptAESKeyWithPeer();
	m_net.SendData(m_serverSock, encryptedAES);
	std::cout << "[Client] Clave AES cifrada y enviada al servidor.\n";
}

void 
Client::SendEncryptedMessage(const std::string& message) {
	std::vector<unsigned char> iv;
	auto cipher = m_crypto.AESEncrypt(message, iv);

	// 1) IV (16)
	m_net.SendData(m_serverSock, iv);

	// 2) Tamano (uint32_t) en network byte order
	uint32_t clen = static_cast<uint32_t>(cipher.size());
	uint32_t nlen = htonl(clen);
	std::vector<unsigned char> len4(reinterpret_cast<unsigned char*>(&nlen),
		reinterpret_cast<unsigned char*>(&nlen) + 4);
	m_net.SendData(m_serverSock, len4);

	// 3) Ciphertext
	m_net.SendData(m_serverSock, cipher);
}

void 
Client::SendEncryptedMessageLoop() {
	std::string msg;
	while (true) {
		std::cout << "Cliente> ";
		std::getline(std::cin, msg);
		if (msg == "/exit") break;

		std::vector<unsigned char> iv;
		auto cipher = m_crypto.AESEncrypt(msg, iv);

		m_net.SendData(m_serverSock, iv);

		uint32_t clen = static_cast<uint32_t>(cipher.size());
		uint32_t nlen = htonl(clen);
		std::vector<unsigned char> len4(reinterpret_cast<unsigned char*>(&nlen),
			reinterpret_cast<unsigned char*>(&nlen) + 4);
		m_net.SendData(m_serverSock, len4);

		m_net.SendData(m_serverSock, cipher);
	}
}

void 
Client::StartReceiveLoop() {
	while (true) {
		// 1) IV (16 bytes)
		auto iv = m_net.ReceiveDataBinary(m_serverSock, 16);
		if (iv.empty()) {
			std::cout << "\n[Client] Conexion cerrada por el servidor.\n";
			break;
		}

		// 2) Tamano (4 bytes, network/big-endian)
		auto len4 = m_net.ReceiveDataBinary(m_serverSock, 4);
		if (len4.size() != 4) {
			std::cout << "[Client] Error al recibir tamano.\n";
			break;
		}
		uint32_t nlen = 0;
		std::memcpy(&nlen, len4.data(), 4);
		uint32_t clen = ntohl(nlen);

		// 3) Ciphertext (clen bytes)
		auto cipher = m_net.ReceiveDataBinary(m_serverSock, static_cast<int>(clen));
		if (cipher.empty()) {
			std::cout << "[Client] Error al recibir datos.\n";
			break;
		}

		// 4) Descifrar y mostrar (bloque decorado)
		std::string plain = m_crypto.AESDecrypt(cipher, iv);
		std::cout
			<< "\n+------------------ from Servidor ------------------+\n"
			<< "| " << plain << "\n"
			<< "+-------------------------------------------------+\n"
			<< "Cliente> ";
		std::cout.flush();
	}
	std::cout << "[Client] ReceiveLoop terminado.\n";
}

void Client::StartChatLoop() {
	// Banner ASCII inicial (sin limpiar pantalla)
	std::cout << "\n====================================================\n";
	std::cout << "=              E2EE Secure Chat - Client           =\n";
	std::cout << "=   RSA handshake + AES-256-CBC. Comandos: /exit   =\n";
	std::cout << "====================================================\n\n";

	std::thread recvThread([&]() {
		StartReceiveLoop();
		});

	SendEncryptedMessageLoop();

	if (recvThread.joinable())
		recvThread.join();
}