#include "com_syswin_temail_vault_sdk_VaultSdk.h"
#include "tsbApi.h"

long setPassword(std::string tid, long code, std::string &key) {
  key = "123456";
  return code;
}

JNIEXPORT jstring JNICALL Java_com_syswin_temail_vault_sdk_VaultSdk_generateKeyPair
  (JNIEnv* env, jobject thisObj, jstring temail) {

  const char* pTemail = env->GetStringUTFChars(temail, NULL);
  tsb::BufferArray publicKey;

  tsb::setTSBSDKFolder("/tmp");
//  tsb::setCallBack(setPassword);
  tsb::ITSBSDK* sdk = tsb::initTSBSDK(pTemail, tsb::tsbCryptAlgType::TECC);

  sdk->tsbGetPubKey(publicKey);

  return env->NewStringUTF(reinterpret_cast<char*>(publicKey.data()));
}
