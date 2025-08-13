#pragma once
#include "Prerequisites.h"
#include <openssl/rsa.h>
#include <openssl/aes.h>

/**
 * CryptoHelper
 * - Gestiona un par de claves RSA (propias) y la clave pública del peer.
 * - Genera y mantiene la clave simétrica AES-256 para cifrado de mensajes.
 * - Expone utilidades para: generar RSA, exportar clave pública, cargar la clave
 *   pública remota, cifrar la clave AES con la pública del peer y descifrarla
 *   con la privada local, y cifrar/descifrar mensajes con AES-256-CBC.
 *
 * Flujo típico:
 *  1) Server/Client: GenerateRSAKeys().
 *  2) Intercambio de claves públicas (GetPublicKeyString / LoadPeerPublicKey).
 *  3) Client: GenerateAESKey() y EncryptAESKeyWithPeer() -> envía al servidor.
 *  4) Server: DecryptAESKey() para obtener la clave AES.
 *  5) Ambos: AESEncrypt/AESDecrypt para el chat.
 */
class
CryptoHelper {
public:
    CryptoHelper();
    ~CryptoHelper();

    // RSA
    void
    GenerateRSAKeys(); // Genera par RSA (2048 bits)

    std::string
    GetPublicKeyString() const; // Devuelve la clave pública en formato PEM (string)

    void
    LoadPeerPublicKey(const std::string& pemKey); // Carga la pública remota desde PEM

    // AES
    void
    GenerateAESKey(); // Genera clave AES-256 aleatoria

    std::vector<unsigned char>
    EncryptAESKeyWithPeer(); // Cifra la clave AES local con la pública del peer

    void
    DecryptAESKey(const std::vector<unsigned char>& encryptedKey); // Descifra la clave AES recibida

    std::vector<unsigned char>
    AESEncrypt(const std::string& plaintext, std::vector<unsigned char>& outIV); // AES-256-CBC

    std::string
    AESDecrypt(const std::vector<unsigned char>& ciphertext,
               const std::vector<unsigned char>& iv); // AES-256-CBC

private:
    RSA* rsaKeyPair; // Par de claves RSA (propias)
    RSA* peerPublicKey; // Clave pública del peer
    unsigned char aesKey[32]; // Clave AES-256 (32 bytes)
};
