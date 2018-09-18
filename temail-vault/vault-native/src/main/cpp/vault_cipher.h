#ifndef VAULT_CIPHER_H
#define VAULT_CIPHER_H

#include <string>
#include <functional>

namespace vault {
  typedef std::vector<char> ByteBuffer;
  typedef std::function<int(const char* message)> ErrorHandler;

  class VaultCipher {
  public:
    virtual void generateKeyPair(std::string &publicKey, std::string &privateKey, ErrorHandler handler) = 0;

    virtual void sign(const char * privateKey, const ByteBuffer &plaintext, ByteBuffer &signature, ErrorHandler handler) = 0;

    virtual bool verify(const char * publicKey, const ByteBuffer &plaintext, const ByteBuffer &signature, ErrorHandler handler) = 0;

    virtual void encrypt(const char * publicKey, const ByteBuffer &plaintext, ByteBuffer &encrypted, ErrorHandler handler) = 0;

    virtual void decrypt(const char * privateKey, const ByteBuffer &encrypted, ByteBuffer &plaintext, ErrorHandler handler) = 0;

    VaultCipher() {};
    virtual ~VaultCipher() {};
  };
}

#endif
