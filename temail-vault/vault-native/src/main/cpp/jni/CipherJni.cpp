#include <jni.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <functional>

using namespace std::placeholders;

#include "com_syswin_temail_vault_jni_CipherJni.h"
#include "fake_vault_cipher.h"
#include "ecc_vault_cipher.h"

#define JAVA_CIPHER_CLASS_NAME "com/syswin/temail/vault/jni/CipherJni"
#define JAVA_KEY_PAIR_CLASS_NAME JAVA_CIPHER_CLASS_NAME "$KeyPair"
#define JAVA_EX_CLASS_NAME "com/syswin/temail/kms/vault/exceptions/VaultCipherException"

class CipherErrorHandler {
  public:
    CipherErrorHandler(JNIEnv *aEnv) : env(aEnv) { };
    ~CipherErrorHandler() { };

    jint throwCipherException(const char *message) {
      jclass exClass = env->FindClass(JAVA_EX_CLASS_NAME);
      return env->ThrowNew(exClass, message);
    };

  private:
    JNIEnv *env;
};

#ifdef __cplusplus
extern "C" {
#endif

static vault::VaultCipher *gCipher;

static jbyteArray toBytes(JNIEnv *env, const std::string& buffer) {
  jbyteArray bytes = env->NewByteArray(buffer.size());
  env->SetByteArrayRegion(bytes, 0, buffer.size(), (const jbyte*)buffer.c_str());
  return bytes;
}

static char* toString(JNIEnv *env, const jbyteArray& array) {
  int len = env->GetArrayLength (array);
  char* buf = (char*) calloc(sizeof(char), len + 1);

  jbyte* jbytes = env->GetByteArrayElements(array, NULL);
  memcpy(buf, jbytes, len);

  env->ReleaseByteArrayElements(array, jbytes, JNI_ABORT);
  return buf;
}

static vault::ByteBuffer toVector(JNIEnv *env, const jstring& string) {
  const char *array = env->GetStringUTFChars(string, NULL);

  vault::ByteBuffer buffer(array, array + strlen(array));
  env->ReleaseStringUTFChars(string, array);

  return buffer;
}

static vault::ByteBuffer bytesToVector(JNIEnv *env, const jbyteArray& array) {
  jbyte* jbytes = env->GetByteArrayElements(array, NULL);
  jsize len = env->GetArrayLength(array);
  char * bytes = (char *)jbytes;
  std::vector<char> buffer;

  for (int i = 0; i < len; i++) {
    buffer.push_back(bytes[i]);
  }

  env->ReleaseByteArrayElements(array, jbytes, JNI_ABORT);
  return buffer;
}

static jbyteArray fromVector(JNIEnv *env, const vault::ByteBuffer& buffer) {
  jbyte* bytes = new jbyte[buffer.size()];
  jbyteArray array = env->NewByteArray(buffer.size());
  for (int i = 0; i < buffer.size(); i++) {
    bytes[i] = (jbyte)buffer[i];
  }

  env->SetByteArrayRegion(array, 0, buffer.size(), bytes);
  delete[] bytes;
  return array;
}

JNIEXPORT jobject JNICALL Java_com_syswin_temail_vault_jni_CipherJni_generateKeyPair
  (JNIEnv *env, jobject obj) {
  std::string sPublicKey;
  std::string sPrivateKey;
  vault::ErrorHandler handler = std::bind(&CipherErrorHandler::throwCipherException, CipherErrorHandler(env), _1);
  gCipher->generateKeyPair(sPublicKey, sPrivateKey, handler);
  
  jclass cls = env->FindClass(JAVA_KEY_PAIR_CLASS_NAME);
  jmethodID constructorId = env->GetMethodID(cls, "<init>", "([B[B)V");

  jbyteArray publicKey = toBytes(env, sPublicKey);
  jbyteArray privateKey = toBytes(env, sPrivateKey);
  jobject keyPair = env->NewObject(cls, constructorId, publicKey, privateKey);
  env->DeleteLocalRef(publicKey);
  env->DeleteLocalRef(privateKey);

  return keyPair;
}

JNIEXPORT jbyteArray JNICALL Java_com_syswin_temail_vault_jni_CipherJni_encrypt
  (JNIEnv *env, jobject obj, jbyteArray publicKey, jstring plaintext) {
  char* key = toString(env, publicKey);
  vault::ByteBuffer encrypted;
  vault::ErrorHandler handler = std::bind(&CipherErrorHandler::throwCipherException, CipherErrorHandler(env), _1);
  gCipher->encrypt(key, toVector(env, plaintext), encrypted, handler);
  free(key);
  return fromVector(env, encrypted);
}

JNIEXPORT jbyteArray JNICALL Java_com_syswin_temail_vault_jni_CipherJni_decrypt
  (JNIEnv *env, jobject obj, jbyteArray privateKey, jbyteArray encrypted) {
  char* key = toString(env, privateKey);
  vault::ByteBuffer plaintext;
  vault::ErrorHandler handler = std::bind(&CipherErrorHandler::throwCipherException, CipherErrorHandler(env), _1);
  gCipher->decrypt(key, bytesToVector(env, encrypted), plaintext, handler);
  free(key);
  return fromVector(env, plaintext);
}

JNIEXPORT jbyteArray JNICALL Java_com_syswin_temail_vault_jni_CipherJni_sign
  (JNIEnv *env, jobject obj, jbyteArray privateKey, jstring plaintext) {
  char* key = toString(env, privateKey);
  vault::ByteBuffer signature;
  vault::ErrorHandler handler = std::bind(&CipherErrorHandler::throwCipherException, CipherErrorHandler(env), _1);
  gCipher->sign(key, toVector(env, plaintext), signature, handler);
  free(key);
  return fromVector(env, signature);
}

JNIEXPORT jboolean JNICALL Java_com_syswin_temail_vault_jni_CipherJni_verify
  (JNIEnv *env, jobject obj, jbyteArray publicKey, jstring plaintext, jbyteArray signature) {
  char* key = toString(env, publicKey);
  vault::ErrorHandler handler = std::bind(&CipherErrorHandler::throwCipherException, CipherErrorHandler(env), _1);
  bool verified = gCipher->verify(key, toVector(env, plaintext), bytesToVector(env, signature), handler);
  free(key);
  return (jboolean) verified;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {
  gCipher = new vault::EccVaultCipher();
  return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
  delete gCipher;
  gCipher = nullptr;
}

#ifdef __cplusplus
}
#endif
