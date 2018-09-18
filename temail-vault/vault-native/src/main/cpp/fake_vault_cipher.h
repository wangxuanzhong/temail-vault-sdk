#ifndef FAKE_VAULT_CIPHER_H
#define FAKE_VAULT_CIPHER_H

#include <string>
#include "vault_cipher.h"

namespace vault {

  class FakeVaultCipher : public VaultCipher {
  public:
    void generateKeyPair(std::string &publicKey, std::string &privateKey);

    void sign(const char * privateKey, const ByteBuffer &plaintext, ByteBuffer &signature);

    bool verify(const char * publicKey, const ByteBuffer &plaintext, const ByteBuffer &signature);

    void encrypt(const char * publicKey, const ByteBuffer &plaintext, ByteBuffer &encrypted);

    void decrypt(const char * privateKey, const ByteBuffer &encrypted, ByteBuffer &plaintext);

    FakeVaultCipher() {};
    ~FakeVaultCipher() {};
  };
}

#endif
