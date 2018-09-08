//
// Created by juzenhon on 2018/9/7.
//
#include <jni.h>
#include <cstring>
#include <iostream>
#include "tsbApi.h"
#include "com_temail_tsb_TSBSdk.h"

extern "C" {

static JavaVM *g_vm = nullptr;

static jobject javaCallback = nullptr;

static tsb::ITSBSDK *g_sdk = nullptr;

static jboolean initTSBSDK(JNIEnv *env, jclass clz, jstring tid, jint type) {
    if (tid == nullptr || (type != 0) && (type != 1)) {
        return JNI_FALSE;
    }


    auto callback = [](std::string tid, long code, std::string &key) -> long {
        if (g_vm == nullptr) {
            return 0;
        }
        JNIEnv *env1 = NULL;
        g_vm->GetEnv((void **) &env1, JNI_VERSION_1_6);
        if (javaCallback && env1) {
            jclass callbackClz = env1->GetObjectClass(javaCallback);
            jmethodID onCallMethodId = env1->GetMethodID(callbackClz, "onResult",
                                                         "(Ljava/lang/String;JLjava/lang/String;)J");
            if (onCallMethodId == nullptr) {
                return 0;
            }
            jstring jstr_tid = env1->NewStringUTF(tid.c_str());
            jstring jstr_key = env1->NewStringUTF(key.c_str());

            jint ret = env1->CallIntMethod(callbackClz, onCallMethodId, jstr_tid,
                                           (jint) code, jstr_key);

            return ret;
        }
        return 0;

    };
    //tsb::setCallBack(callback);

    const char *c_tid = env->GetStringUTFChars(tid, NULL);
    tsb::ITSBSDK *sdk = tsb::initTSBSDK(c_tid, tsb::tsbCryptAlgType::TECC);

    if (c_tid) {
        env->ReleaseStringUTFChars(tid, c_tid);
    }
    jboolean Inited = sdk != nullptr ? JNI_TRUE : JNI_FALSE;

    if (Inited) {
        g_sdk = sdk;
    }

    return Inited;

}

static void setTSBSDKFolder(JNIEnv *env, jclass clz, jstring folder) {

    const char *c_folder = nullptr;
    if (folder) {
        c_folder = env->GetStringUTFChars(folder, NULL);
    }
    tsb::setTSBSDKFolder(c_folder);

    if (c_folder) {
        env->ReleaseStringUTFChars(folder, c_folder);
    }

}

static void setCallback(JNIEnv *env, jclass clz, jobject callback) {
    if (javaCallback != nullptr) {
        env->DeleteGlobalRef(javaCallback);
    }
    javaCallback = env->NewGlobalRef(callback);

}


static void destroyTSBSDK(JNIEnv *env, jclass clz, jstring tid) {

    const char *c_tid = nullptr;
    if (tid) {
        c_tid = env->GetStringUTFChars(tid, NULL);
    }
    tsb::destoryTSBSDK(c_tid);

    if (c_tid) {
        env->ReleaseStringUTFChars(tid, c_tid);
    }

}

//-----------------------    sdk    ---------------

static void getByteBufferFromByteArray(JNIEnv *env,jbyteArray arr,tsb::BufferArray& buffer){
    jbyte *arr_bytes = env->GetByteArrayElements(arr, NULL);
    jint j_size = env->GetArrayLength(arr);

    if(j_size == 0){
        return;
    }
    buffer.resize(j_size);
    memcpy(&buffer[0],arr_bytes,j_size);
    env->ReleaseByteArrayElements(arr,arr_bytes,0);
}

static jbyteArray getByteArrayFromBuffer(JNIEnv *env,tsb::BufferArray& buffer){

    jbyteArray arr = env->NewByteArray(buffer.size());
    env->SetByteArrayRegion(arr,0,buffer.size(),(const jbyte*)&buffer[0]);
    return arr;
}

static jbyteArray getPublicKey(JNIEnv *env, jclass clz, jstring tid) {
    tsb::BufferArray publicKey;
    long code = g_sdk->tsbGetPubKey(publicKey);

    if(code == ERR_SUCCESS){
        return getByteArrayFromBuffer(env, publicKey);
    }
    return nullptr;
}

/**
 * 加密数据
 * @param env
 * @param clz
 * @param type
 * @param key
 * @param plainText
 * @return
 */
static jbyteArray tsbEncryptData(JNIEnv *env, jclass clz, jint type, jbyteArray key, jbyteArray plainText) {
    if (g_sdk == nullptr || key == nullptr || plainText == nullptr) {
        return nullptr;
    }
    tsb::BufferArray bf_key;
    getByteBufferFromByteArray(env,key,bf_key);

    tsb::BufferArray bf_plain;
    getByteBufferFromByteArray(env,plainText,bf_plain);

    tsb::BufferArray outBuffer;
    long code = g_sdk->tsbEncryptData((tsb::tsbCryptAlgType) type,bf_key,bf_plain,outBuffer);
    if(code == ERR_SUCCESS){
        return getByteArrayFromBuffer(env,outBuffer);
    }
    return nullptr;
}

/**
 * 解密数据
 * @param env
 * @param clz
 * @param type
 * @param key
 * @param secData
 * @return
 */
static jbyteArray tsbDecryptData(JNIEnv *env, jclass clz, jint type, jbyteArray key, jbyteArray secData) {
    if (g_sdk == nullptr || key == nullptr) {
        return nullptr;
    }
    tsb::BufferArray bf_key;
    getByteBufferFromByteArray(env,key,bf_key);

    tsb::BufferArray bf_data;
    getByteBufferFromByteArray(env,secData,bf_data);

    tsb::BufferArray outBuffer;
    long code = g_sdk->tsbDecryptData((tsb::tsbCryptAlgType) type,bf_key,bf_data,outBuffer);
    if(code == ERR_SUCCESS){
        return getByteArrayFromBuffer(env,outBuffer);
    }
    return nullptr;
}


/**
 * 内容签名
 * @param env
 * @param clz
 * @param context
 * @return
 */
static jbyteArray tsbSignature(JNIEnv *env, jclass clz, jbyteArray context) {
    if (g_sdk == nullptr) {
        return nullptr;
    }

    tsb::BufferArray bf_context;
    getByteBufferFromByteArray(env,context,bf_context);

    tsb::BufferArray bf_sigBuffer;
    long code = g_sdk->tsbSignature(bf_context,bf_sigBuffer);
    if(code == ERR_SUCCESS){
        return getByteArrayFromBuffer(env,bf_sigBuffer);
    }
    return nullptr;
}


/**
 * 签名校验
 * @param env
 * @param clz
 * @param context
 * @return
 */
static jboolean tsbVerifySignature(JNIEnv *env, jclass clz, jbyteArray context,jbyteArray sig) {
    if (g_sdk == nullptr) {
        return JNI_FALSE;
    }

    tsb::BufferArray bf_context;
    getByteBufferFromByteArray(env,context,bf_context);

    tsb::BufferArray bf_sigBuffer;
    getByteBufferFromByteArray(env,sig,bf_sigBuffer);

    long code = g_sdk->tsbSignature(bf_context,bf_sigBuffer);
    return code == ERR_SUCCESS;
}







//--------------------------------jni_onload---------------

JNINativeMethod nativeMethods[] = {{"initTSBSDK",      "(Ljava/lang/String;I)Z",              (void *) initTSBSDK},
                                   {"setTSBSDKFolder", "(Ljava/lang/String;)V",               (void *) setTSBSDKFolder},
                                   {"setKeyCallback",     "(Lcom/temail/tsb/TSBSdk$KeyCallback;)V", (void *) setCallback},
                                   {"destroyTSBSDK",   "(Ljava/lang/String;)V",               (void *) destroyTSBSDK},
                                   {"getPublicKey",   "(Ljava/lang/String;)[B",               (void *) getPublicKey},
                                   {"encryptData",   "(I[B[B)[B",               (void *) tsbEncryptData},
                                   {"decryptData",   "(I[B[B)[B",               (void *) tsbDecryptData},
                                   {"signature",   "([B)[B",               (void *) tsbSignature},
                                   {"verifySignature",   "([B[B)Z",               (void *) tsbVerifySignature},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {
    g_vm = jvm;
    JNIEnv *env = nullptr;
    if (jvm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }
    jclass clz = env->FindClass("com/temail/tsb/TSBSdk");

    env->RegisterNatives(clz, nativeMethods, sizeof(nativeMethods) / sizeof(JNINativeMethod));
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    g_vm = nullptr;
}

}
