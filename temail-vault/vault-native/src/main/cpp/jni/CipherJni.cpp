#include <jni.h>
#include <cstring>
#include <iostream>

#include "com_syswin_temail_vault_jni_CipherJni.h"
#include "hello.h"

#define JAVA_CIPHER_CLASS_NAME "com/syswin/temail/vault/jni/CipherJni"
#define JAVA_KEY_PAIR_CLASS_NAME JAVA_CIPHER_CLASS_NAME "$KeyPair"

#ifdef __cplusplus
extern "C" {
#endif

static jbyteArray toBytes(JNIEnv *env, const char* buffer){
  jbyteArray bytes = env->NewByteArray(strlen(buffer));
  env->SetByteArrayRegion(bytes, 0, strlen(buffer), (const jbyte*)buffer);
  return bytes;
}

JNIEXPORT jobject JNICALL Java_com_syswin_temail_vault_jni_CipherJni_generateKeyPair
  (JNIEnv *env, jobject obj) {
  jclass cls = env->FindClass(JAVA_KEY_PAIR_CLASS_NAME);
  jmethodID constructorId = env->GetMethodID(cls, "<init>", "([B[B)V");

  jbyteArray publicKey = toBytes(env, "publicKey");
  jbyteArray privateKey = toBytes(env, "privateKey");
  jobject keyPair = env->NewObject(cls, constructorId, publicKey, privateKey);
  env->DeleteLocalRef(publicKey);
  env->DeleteLocalRef(privateKey);

  return keyPair;
}

JNIEXPORT jbyteArray JNICALL Java_com_syswin_temail_vault_jni_CipherJni_encrypt
  (JNIEnv *env, jobject obj, jbyteArray publicKey, jstring plaintext) {
  return nullptr;
}

JNIEXPORT jbyteArray JNICALL Java_com_syswin_temail_vault_jni_CipherJni_decrypt
  (JNIEnv *env, jobject obj, jbyteArray privateKey, jbyteArray encrypted) {
  return nullptr;
}

JNIEXPORT jbyteArray JNICALL Java_com_syswin_temail_vault_jni_CipherJni_sign
  (JNIEnv *env, jobject obj, jbyteArray privateKey, jstring plaintext) {
  return nullptr;
}

JNIEXPORT jboolean JNICALL Java_com_syswin_temail_vault_jni_CipherJni_verify
  (JNIEnv *env, jobject obj, jbyteArray publicKey, jstring plaintext, jbyteArray signature) {
  return JNI_TRUE;
}

#ifdef __cplusplus
}
#endif
