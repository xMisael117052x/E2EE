#pragma once
#include "Prerequisites.h"
#include <openssl/rsa.h>
#include <openssl/aes.h>

class
    CryptoHelper {
public:
    CryptoHelper();
    ~CryptoHelper();

    // RSA
    void
    GenerateRSAKeys();

    std::string
    GetPublicKeyString() const;

    void
    LoadPeerPublicKey(const std::string& pemKey);

    // AES
    void
    GenerateAESKey();

    std::vector<unsigned char>
    EncryptAESKeyWithPeer();

    void
    DecryptAESKey(const std::vector<unsigned char>& encryptedKey);

    std::vector<unsigned char>
    AESEncrypt(const std::string& plaintext, std::vector<unsigned char>& outIV);

    std::string
    AESDescrypt(const std::vector<unsigned char>& ciphertext,
                const std::vector<unsigned char>& iv);

private:
    RSA* rsaKeyPair;
    RSA* peerPublicKey;
    unsigned char aesKey[32];
};
