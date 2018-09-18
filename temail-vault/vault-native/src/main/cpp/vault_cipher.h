#ifndef VAULT_CIPHER_H
#define VAULT_CIPHER_H

#include <string>

namespace vault {
  typedef std::vector<char> ByteBuffer;

  class VaultCipher {
  public:
    virtual void generateKeyPair(std::string &publicKey, std::string &privateKey) = 0;

    virtual void sign(const char * privateKey, const ByteBuffer &plaintext, ByteBuffer &signature) = 0;

    virtual bool verify(const char * publicKey, const ByteBuffer &plaintext, const ByteBuffer &signature) = 0;

    virtual void encrypt(const char * publicKey, const ByteBuffer &plaintext, ByteBuffer &encrypted) = 0;

    virtual void decrypt(const char * privateKey, const ByteBuffer &encrypted, ByteBuffer &plaintext) = 0;

    VaultCipher() {};
    virtual ~VaultCipher() {};
  };
}

#endif
