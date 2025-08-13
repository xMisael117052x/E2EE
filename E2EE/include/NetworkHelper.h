#pragma once
#include "Prerequisites.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

/**
 * @brief Utilidades de red basadas en WinSock para TCP (IPv4).
 *
 * Responsabilidades:
 *  - Inicializar/limpiar WinSock (WSAStartup/WSACleanup).
 *  - Crear socket de servidor, bind, listen y aceptar clientes.
 *  - Conectar como cliente a un servidor remoto.
 *  - Enviar/recibir datos en modos texto y binario, con helpers para enviar todo
 *    el buffer y recibir exactamente N bytes.
 *
 * Notas:
 *  - Esta clase mantiene un unico SOCKET (m_serverSocket) que representa el
 *    socket de escucha (en modo servidor) o el socket conectado (en modo cliente).
 */
class
NetworkHelper {
public:
    /** @brief Construye el helper e inicializa WinSock 2.2. */
    NetworkHelper();

    /** @brief Libera el socket si sigue abierto y llama a WSACleanup si procedia. */
    ~NetworkHelper();

    /**
     * @brief Inicia un servidor TCP en el puerto indicado.
     * @param port Puerto TCP (0-65535) donde escuchar.
     * @return true si se inicio correctamente; false en caso de error.
     */
    bool
    StartServer(int port);

    /**
     * @brief Acepta un cliente entrante en el socket de escucha.
     * @return SOCKET del cliente aceptado o INVALID_SOCKET en error.
     */
    SOCKET
    AcceptClient();

    /**
     * @brief Conecta a un servidor remoto via TCP.
     * @param ip Direccion IPv4 en formato string (ej. "127.0.0.1").
     * @param port Puerto TCP del servidor.
     * @return true si se conecto correctamente; false si fallo.
     */
    bool
    ConnectToServer(const std::string& ip, int port);

    /**
     * @brief Envia un string por el socket.
     * @param socket SOCKET destino (cliente o servidor).
     * @param data Datos en texto a enviar.
     * @return true si se envio todo; false si hubo error.
     */
    bool
    SendData(SOCKET socket, const std::string& data);

    /**
     * @brief Envia un buffer binario por el socket.
     * @param socket SOCKET destino (cliente o servidor).
     * @param data Buffer binario a enviar.
     * @return true si se envio todo; false si hubo error.
     */
    bool
    SendData(SOCKET socket, const std::vector<unsigned char>& data);

    /**
     * @brief Recibe datos en texto (hasta 4096 bytes en una llamada a recv).
     * @param socket SOCKET desde el que se reciben datos.
     * @return string con los bytes recibidos.
     */
    std::string
    ReceiveData(SOCKET socket);

    /**
     * @brief Recibe exactamente "size" bytes o devuelve {} si falla.
     * @param socket SOCKET desde el que se reciben datos.
     * @param size Numero exacto de bytes a recibir.
     * @return Vector con los bytes recibidos o vacio si hubo error/cierre.
     */
    std::vector<unsigned char>
    ReceiveDataBinary(SOCKET socket, int size = 0);

    /**
     * @brief Cierra de forma segura un SOCKET.
     * @param socket SOCKET a cerrar.
     */
    void
    close(SOCKET socket);

    /**
     * @brief Envia la totalidad de un buffer, reintentando hasta agotar.
     * @param s SOCKET.
     * @param data Puntero al buffer origen.
     * @param len Longitud en bytes del buffer.
     * @return true si se envio todo; false si fallo send.
     */
    bool
    SendAll(SOCKET s, const unsigned char* data, int len);

    /**
     * @brief Recibe exactamente len bytes, reintentando hasta completar o fallar.
     * @param s SOCKET.
     * @param out Buffer destino (debe tener al menos len bytes).
     * @param len Numero de bytes a recibir.
     * @return true si se recibio todo; false si fallo o se cerro.
     */
    bool
    ReceiveExact(SOCKET s, unsigned char* out, int len);

public:
    /**
     * @brief Socket principal del helper:
     *  - modo servidor: socket de escucha.
     *  - modo cliente: socket conectado al servidor.
     */
    SOCKET m_serverSocket = -1;

private:
    /** @brief Indica si WSAStartup se ejecuto con exito y se debe hacer WSACleanup. */
    bool m_initialized;
};
