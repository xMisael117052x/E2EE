#pragma once
#include <thread>

#include "NetworkHelper.h"
#include "CryptoHelper.h"

/**
 * @brief Servidor E2EE (End-to-End Encryption).
 *
 * Responsabilidades:
 *  - Aceptar un cliente TCP.
 *  - Intercambiar claves RSA/AES (RSA publica, AES simetrica).
 *  - Iniciar bucles de recepcion/envio en paralelo para un chat continuo.
 *  - Protocolo de mensaje: [IV(16)] [Len(4, big-endian)] [Ciphertext].
 */
class
Server {
public:
    /** @brief Constructor por defecto. */
    Server() = default;

    /**
     * @brief Construye el servidor con puerto y genera claves RSA.
     * @param port Puerto TCP en el que escuchara el servidor.
     */
    Server(int port);

    /** @brief Destructor: cierra el socket del cliente si esta abierto. */
    ~Server();

    /**
     * @brief Inicia el socket servidor y escucha en el puerto indicado.
     * @return true si se inicio correctamente; false en caso de error.
     */
    bool
    Start();

    /**
     * @brief Espera a que un cliente se conecte y realiza el intercambio de claves.
     */
    void
    WaitForClient();

    /**
     * @brief Recibe un unico mensaje cifrado (uso puntual; el chat usa los bucles).
     */
    void
    ReceiveEncryptedMessage();

    /**
     * @brief Bucle de recepcion: lee IV, longitud y ciphertext, descifra y muestra.
     */
    void
    StartReceiveLoop();

    /**
     * @brief Bucle de envio: toma input de consola, cifra y envia (comando /exit para salir).
     */
    void
    SendEncryptedMessageLoop();

    /**
     * @brief Lanza el bucle de recepcion en un hilo y mantiene el envio en el principal.
     */
    void
    StartChatLoop();

private:
    int m_port = 0;
    SOCKET m_clientSock = INVALID_SOCKET;
    NetworkHelper m_net;
    CryptoHelper m_crypto;
    std::thread m_rxThread;
    std::atomic<bool> m_running{false};
};
