#include "ecc_vault_cipher.h"
#include "eccApi.h"
#include <vector>
#include <algorithm>
#include <string>

using namespace vault;
using namespace ECC;

EccVaultCipher::EccVaultCipher() {
  errorMessages.insert(std::make_pair(ERR_LOGINKEY_INVALID, "Invalid login key"));
  errorMessages.insert(std::make_pair(ERR_TID_INVALID, "Invalid user ID"));
  errorMessages.insert(std::make_pair(ERR_CFSFOLDER_INVALID, "ERR_CFSFOLDER_INVALID"));
  errorMessages.insert(std::make_pair(ERR_CFSFILE_INVALID, "ERR_CFSFILE_INVALID"));
  errorMessages.insert(std::make_pair(ERR_SAFEKEY_INVALID, "ERR_SAFEKEY_INVALID"));
  errorMessages.insert(std::make_pair(ERR_FILEENCRY_FAILED, "ERR_FILEENCRY_FAILED"));
  errorMessages.insert(std::make_pair(ERR_ALG_INVALID, "Unsupported algorithm"));
  errorMessages.insert(std::make_pair(ERR_TSBFOLDER_DUPFOLDER, "ERR_TSBFOLDER_DUPFOLDER"));
  errorMessages.insert(std::make_pair(ERR_TSBCALLBACK_INVALID, "ERR_TSBCALLBACK_INVALID"));
  errorMessages.insert(std::make_pair(ERR_KEY_INVALID, "ERR_KEY_INVALID"));
  errorMessages.insert(std::make_pair(ERR_IV_INVALID, "ERR_IV_INVALID"));
  errorMessages.insert(std::make_pair(ERR_SAFETONORMAL_FAILED, "ERR_SAFETONORMAL_FAILED"));
  errorMessages.insert(std::make_pair(ERR_NORMALTOSAFE_FAILED, "ERR_NORMALTOSAFE_FAILED"));
  errorMessages.insert(std::make_pair(ERR_RESETPWD_FAILED, "ERR_RESETPWD_FAILED"));
  errorMessages.insert(std::make_pair(ERR_OLDLOGINPWD_INVALID, "ERR_OLDLOGINPWD_INVALID"));
  errorMessages.insert(std::make_pair(ERR_MEMORY_FAILED, "ERR_MEMORY_FAILED"));
  errorMessages.insert(std::make_pair(ERR_PUBORPRIKEY_INVALID, "ERR_PUBORPRIKEY_INVALID"));
  errorMessages.insert(std::make_pair(ERR_ENCRYORDECRY_FAILED, "ERR_ENCRYORDECRY_FAILED"));
  errorMessages.insert(std::make_pair(ERR_EVP_INVALID, "ERR_EVP_INVALID"));
  errorMessages.insert(std::make_pair(ERR_SIGNORDESIGN_FAILED, "ERR_SIGNORDESIGN_FAILED"));
  errorMessages.insert(std::make_pair(ERR_PARAM_INVALID, "ERR_PARAM_INVALID"));
  errorMessages.insert(std::make_pair(ERR_NAME_INVALID, "ERR_NAME_INVALID"));
  errorMessages.insert(std::make_pair(ERR_PID_INVALID, "ERR_PID_INVALID"));
  errorMessages.insert(std::make_pair(ERR_CREATEMEM_FAILED, "ERR_CREATEMEM_FAILED"));
  errorMessages.insert(std::make_pair(ERR_AES_KEYLENGTH_INVALID, "ERR_AES_KEYLENGTH_INVALID"));
  errorMessages.insert(std::make_pair(ERR_EVPINIT_FAILED, "ERR_EVPINIT_FAILED"));
  errorMessages.insert(std::make_pair(ERR_EVPENC_FAILED, "ERR_EVPENC_FAILED"));
  errorMessages.insert(std::make_pair(ERR_EVPDEC_FAILED, "ERR_EVPDEC_FAILED"));
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
  return ecc_verify(publicKey, plaintext, signature) == ERR_SUCCESS;
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
