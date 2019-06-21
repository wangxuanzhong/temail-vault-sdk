#ifndef __TSB_ALGAPI_H_
#define __TSB_ALGAPI_H_

#include <vector>
#include <chrono>
#include <functional>
#include "tsbCommonApi.h"

using namespace std;
using namespace std::chrono;

typedef enum
{
	ECB = 0, 
    CBC = 1
	/*
    CFB = 2 //temporary not support
	*/
}_AESMode;

namespace ALG
{
	/*ECC notice the key is safe base64 format*/
	int64_t ecc_generateKey(std::string &pubKey,std::string &priKey);
	int64_t ecc_sign(const char * priKey, const BufferArray &context, BufferArray & sigBuffer);
	int64_t ecc_verify(const char * pubKey, const BufferArray &context, const BufferArray &sigBuffer);
	int64_t ecc_encryptData(const char * pubKey, const BufferArray &context, BufferArray &sec_buf);
	int64_t ecc_decryptData(const char * priKey, const BufferArray &context, BufferArray &text_buf);

	void *ecc_getkeybyPrikey(const std::string &priKey);
	void *ecc_getkeybyPubkey(const std::string &pubKey);
	/*AES*/
	int64_t aes_encryptData(const BufferArray &src, BufferArray &des, const char *key, int32_t keyLen, const char * IV, int32_t iMode);
	int64_t aes_decryptData(const BufferArray &src, BufferArray &des, const char *key, int32_t keyLen, const char * IV, int32_t iMode);
	int64_t aes_encryptCCM(unsigned char *plaintext, int32_t plaintext_len, unsigned char *aad,
		int32_t aad_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int32_t *cipherLen, unsigned char *tag, int32_t *tagLen);
	int64_t aes_decryptCCM(unsigned char *ciphertext, int32_t ciphertext_len, unsigned char *aad,
		int32_t aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv, unsigned char *plaintext,int32_t *plainLen);

	/*MD5*/
	int64_t md5_encrypt_file(char *path, int32_t md5_len,BufferArray &output);
	int64_t md5_encrypt_str(unsigned char *str, int32_t len, int32_t md5_len, BufferArray &output);

	/*SHA*/
	int64_t sha256(const unsigned char *str,int32_t len,std::vector<unsigned char> &output);
	int64_t sha512(const unsigned char *str, int32_t len,std::vector<unsigned char> &output);
	int64_t sha3_512(const unsigned char *str,int32_t len,std::vector<unsigned char> &output);
	int64_t sha3_256(const unsigned char *str, int32_t len,std::vector<unsigned char> &output);
	int64_t shaRand(const unsigned char *str, int32_t inputLen,int32_t outLen,std::vector<unsigned char> &output);
	bool PKCS5_PBKDF2_HMAC(const char *pass, int32_t passlen,unsigned char *salt, int32_t saltlen, int32_t iter,
		int32_t keylen, unsigned char *out, int32_t EVP_SHA);
}

#endif

