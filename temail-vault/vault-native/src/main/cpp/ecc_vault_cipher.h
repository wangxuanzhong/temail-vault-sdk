#ifndef ECC_VAULT_CIPHER_H
#define ECC_VAULT_CIPHER_H

#include <string>
#include "vault_cipher.h"

namespace vault {

  class EccVaultCipher : public VaultCipher {
  public:
    void generateKeyPair(std::string &publicKey, std::string &privateKey, ErrorHandler handler);

    void sign(const char * privateKey, const ByteBuffer &plaintext, ByteBuffer &signature, ErrorHandler handler);

    bool verify(const char * publicKey, const ByteBuffer &plaintext, const ByteBuffer &signature, ErrorHandler handler);

    void encrypt(const char * publicKey, const ByteBuffer &plaintext, ByteBuffer &encrypted, ErrorHandler handler);

    void decrypt(const char * privateKey, const ByteBuffer &encrypted, ByteBuffer &plaintext, ErrorHandler handler);

    EccVaultCipher() {};
    ~EccVaultCipher() {};
  };
}

#endif
