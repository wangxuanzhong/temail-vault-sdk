#include "ecc_vault_cipher.h"
#include "eccApi.h"
#include <vector>
#include <algorithm>
#include <string>

using namespace vault;
using namespace ECC;

void EccVaultCipher::generateKeyPair(std::string &publicKey, std::string &privateKey, ErrorHandler handler) {
  ecc_generateKey(publicKey, privateKey);
}

void EccVaultCipher::sign(const char * privateKey, const ByteBuffer &plaintext, ByteBuffer &signature, ErrorHandler handler) {
  ecc_sign(privateKey, plaintext, signature);
}

bool EccVaultCipher::verify(const char * publicKey, const ByteBuffer &plaintext, const ByteBuffer &signature, ErrorHandler handler) {
  return ecc_verify(publicKey, plaintext, signature) == ERR_SUCCESS;
}

void EccVaultCipher::encrypt(const char * publicKey, const ByteBuffer &plaintext, ByteBuffer &encrypted, ErrorHandler handler) {
  ecc_encryptData(publicKey, plaintext, encrypted);
}

void EccVaultCipher::decrypt(const char * privateKey, const ByteBuffer &encrypted, ByteBuffer &plaintext, ErrorHandler handler) {
  ecc_decryptData(privateKey, encrypted, plaintext);
}
