#include "com_syswin_temail_vault_sdk_VaultSdk.h"
#include "tsbApi.h"

JNIEXPORT jstring JNICALL Java_com_syswin_temail_vault_sdk_VaultSdk_generateKeyPair
  (JNIEnv* env, jobject thisObj, jstring temail) {

  const char* pTemail = env->GetStringUTFChars(temail, NULL);
  tsb::BufferArray publicKey;

  tsb::setTSBSDKFolder("/tmp");
  tsb::initTSBSDK(pTemail, tsb::tsbCryptAlgType::TAES256CBC, pTemail)->tsbGetPubKey(publicKey);

  return env->NewStringUTF(reinterpret_cast<char*>(publicKey.data()));
}
