#include <openssl/crypto.h>
#include <iostream>

int
main()
{
    std::cout << "Version de Openssl: " << OpenSSL_version(OPENSSL_VERSION) << std::endl;
    return 0;
}
