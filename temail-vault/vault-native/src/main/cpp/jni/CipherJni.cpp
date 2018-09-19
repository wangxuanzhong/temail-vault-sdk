#include <jni.h>
#include <cstring>
#include <iostream>
#include <vector>

#include "com_syswin_temail_vault_jni_CipherJni.h"
#include "fake_vault_cipher.h"
#include "ecc_vault_cipher.h"

#define JAVA_CIPHER_CLASS_NAME "com/syswin/temail/vault/jni/CipherJni"
#define JAVA_KEY_PAIR_CLASS_NAME JAVA_CIPHER_CLASS_NAME "$KeyPair"
#define JAVA_EX_CLASS_NAME "com/syswin/temail/kms/vault/exceptions/VaultCipherException"

#ifdef __cplusplus
extern "C" {
#endif

static vault::VaultCipher *gCipher;
static JavaVM *gJvm;

static jint throwCipherException(const char *message) {
  JNIEnv *env;
  if (gJvm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
   return -1;
  }

  jclass exClass = env->FindClass(JAVA_EX_CLASS_NAME);
  return env->ThrowNew(exClass, message);
}

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
  gCipher->generateKeyPair(sPublicKey, sPrivateKey, throwCipherException);
  
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
  gCipher->encrypt(key, toVector(env, plaintext), encrypted, throwCipherException);
  free(key);
  return fromVector(env, encrypted);
}

JNIEXPORT jbyteArray JNICALL Java_com_syswin_temail_vault_jni_CipherJni_decrypt
  (JNIEnv *env, jobject obj, jbyteArray privateKey, jbyteArray encrypted) {
  char* key = toString(env, privateKey);
  vault::ByteBuffer plaintext;
  gCipher->decrypt(key, bytesToVector(env, encrypted), plaintext, throwCipherException);
  free(key);
  return fromVector(env, plaintext);
}

JNIEXPORT jbyteArray JNICALL Java_com_syswin_temail_vault_jni_CipherJni_sign
  (JNIEnv *env, jobject obj, jbyteArray privateKey, jstring plaintext) {
  char* key = toString(env, privateKey);
  vault::ByteBuffer signature;
  gCipher->sign(key, toVector(env, plaintext), signature, throwCipherException);
  free(key);
  return fromVector(env, signature);
}

JNIEXPORT jboolean JNICALL Java_com_syswin_temail_vault_jni_CipherJni_verify
  (JNIEnv *env, jobject obj, jbyteArray publicKey, jstring plaintext, jbyteArray signature) {
  char* key = toString(env, publicKey);
  bool verified = gCipher->verify(key, toVector(env, plaintext), bytesToVector(env, signature), throwCipherException);
  free(key);
  return (jboolean) verified;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {
  gJvm = jvm;
  gCipher = new vault::FakeVaultCipher();
  return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
  delete gCipher;
  gCipher = nullptr;
  gJvm = nullptr;
}

#ifdef __cplusplus
}
#endif
