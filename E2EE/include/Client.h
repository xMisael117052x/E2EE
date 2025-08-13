#pragma once
#include "NetworkHelper.h"
#include "CryptoHelper.h"
#include "Prerequisites.h"

/**
 * Cliente E2EE (End-to-End Encryption)
 * Responsabilidades:
 * - Conectar via TCP a un servidor dado (IP/puerto)
 * - Intercambiar claves RSA (recibe publica del servidor y envia la propia)
 * - Enviar la clave AES generada localmente cifrada con la clave publica del servidor
 * - Participar en un chat seguro en paralelo (recepcion y envio simultaneos)
 *
 * Protocolo de mensajes de chat:
 *   [IV(16 bytes)] [Len(4 bytes, big-endian)] [Ciphertext]
 * Donde Ciphertext es AES-256-CBC(plaintext, IV, key) y Len es el tamaño del ciphertext.
 * Comando disponible en consola: /exit para salir del bucle de envio.
 */
class
Client {
public:
    /** @brief Construccion por defecto. */
    Client() = default;

    /**
     * @brief Inicializa IP/puerto y prepara claves RSA/AES.
     * @param ip Direccion IPv4 del servidor.
     * @param port Puerto TCP del servidor.
     */
    Client(const std::string& ip, int port);

    /** @brief Cierra el socket si sigue abierto. */
    ~Client();
    
    /** @brief Establece la conexion TCP con el servidor. */
    bool 
    Connect();
    
    /** @brief Intercambia claves publicas RSA con el servidor. */
    void 
    ExchangeKeys();
    
    /** @brief Cifra la clave AES local con la publica del servidor y la envia. */
    void 
    SendAESKeyEncrypted();
    
    /** @brief Envia un unico mensaje cifrado. */
    void 
    SendEncryptedMessage(const std::string& message);

    /** @brief Bucle de envio: lee de consola, cifra y envia hasta /exit. */
    void
    SendEncryptedMessageLoop();

    /** @brief Arranca recepcion en hilo y mantiene envio en el principal. */
    void
    StartChatLoop();

    /** @brief Bucle de recepcion: recibe IV, longitud y ciphertext; descifra y muestra. */
    void 
    StartReceiveLoop();

private:
    std::string m_ip;
    int m_port = 0;
    SOCKET m_serverSock = INVALID_SOCKET;
    NetworkHelper m_net;
    CryptoHelper m_crypto;
};
