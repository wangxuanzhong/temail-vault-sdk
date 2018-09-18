#include "fake_vault_cipher.h"
#include <vector>
#include <algorithm>
#include <string>

using namespace vault;

void FakeVaultCipher::generateKeyPair(std::string &publicKey, std::string &privateKey) {
  publicKey = "hello";
  privateKey = "world";
}

void FakeVaultCipher::sign(const char * privateKey, const ByteBuffer &plaintext, ByteBuffer &signature) {
  char const *token = " of ";
  signature.insert(signature.end(), privateKey, privateKey + strlen(privateKey));
  signature.insert(signature.end(), token, token + strlen(token));
  signature.insert(signature.end(), plaintext.begin(), plaintext.end());
}

bool FakeVaultCipher::verify(const char * publicKey, const ByteBuffer &plaintext, const ByteBuffer &signature) {
  return strcmp(publicKey, "hello") == 0
    && std::string(plaintext.begin(), plaintext.end()) == "Sean"
    && std::string(signature.begin(), signature.end()) == "Sean";
}

void FakeVaultCipher::encrypt(const char * publicKey, const ByteBuffer &plaintext, ByteBuffer &encrypted) {
  encrypted.insert(encrypted.end(), publicKey, publicKey + strlen(publicKey));
  encrypted.push_back(' ');
  encrypted.insert(encrypted.end(), plaintext.begin(), plaintext.end());
}

void FakeVaultCipher::decrypt(const char * privateKey, const ByteBuffer &encrypted, ByteBuffer &plaintext) {
  char const *token = "'s ";
  plaintext.insert(plaintext.end(), encrypted.begin(), encrypted.end());
  plaintext.insert(plaintext.end(), token, token + strlen(token));
  plaintext.insert(plaintext.end(), privateKey, privateKey + strlen(privateKey));
}
