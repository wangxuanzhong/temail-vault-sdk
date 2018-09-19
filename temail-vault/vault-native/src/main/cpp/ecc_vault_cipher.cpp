#include "ecc_vault_cipher.h"
#include "eccApi.h"
#include <vector>
#include <algorithm>
#include <string>

using namespace vault;
using namespace ECC;

EccVaultCipher::EccVaultCipher() {
  errorMessages.insert(std::make_pair(ERR_PUBORPRIKEY_INVALID, "Invalid public or private key"));
  errorMessages.insert(std::make_pair(ERR_ENCRYORDECRY_FAILED, "Failed to encrypt/decrypt message"));
  errorMessages.insert(std::make_pair(ERR_EVP_INVALID, "Failed to initialize ECC cipher module"));
  errorMessages.insert(std::make_pair(ERR_SIGNORDESIGN_FAILED, "Failed to sign/verify message"));
  errorMessages.insert(std::make_pair(ERR_PARAM_INVALID, "Invalid parameter"));
}

void EccVaultCipher::generateKeyPair(std::string &publicKey, std::string &privateKey, ErrorHandler handler) {
  int ret = ecc_generateKey(publicKey, privateKey);
  if (ret != ERR_SUCCESS)
    handler(errorMessages[ret]);
}

void EccVaultCipher::sign(const char * privateKey, const ByteBuffer &plaintext, ByteBuffer &signature, ErrorHandler handler) {
  int ret = ecc_sign(privateKey, plaintext, signature);
  if (ret != ERR_SUCCESS)
    handler(errorMessages[ret]);
}

bool EccVaultCipher::verify(const char * publicKey, const ByteBuffer &plaintext, const ByteBuffer &signature, ErrorHandler handler) {
  int ret = ecc_verify(publicKey, plaintext, signature);
  if (ret != ERR_SUCCESS)
      handler(errorMessages[ret]);
  return ret == ERR_SUCCESS;
}

void EccVaultCipher::encrypt(const char * publicKey, const ByteBuffer &plaintext, ByteBuffer &encrypted, ErrorHandler handler) {
  int ret = ecc_encryptData(publicKey, plaintext, encrypted);
  if (ret != ERR_SUCCESS)
    handler(errorMessages[ret]);
}

void EccVaultCipher::decrypt(const char * privateKey, const ByteBuffer &encrypted, ByteBuffer &plaintext, ErrorHandler handler) {
  int ret = ecc_decryptData(privateKey, encrypted, plaintext);
  if (ret != ERR_SUCCESS)
    handler(errorMessages[ret]);
}
