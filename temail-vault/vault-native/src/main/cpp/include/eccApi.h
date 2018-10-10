#ifndef __TSB_ECCAPI_H_
#define __TSB_ECCAPI_H_

#include <vector>
#include <chrono>
#include <functional>

using namespace std;
using namespace std::chrono;

#define ERR_SUCCESS          0
#define ERR_PUBORPRIKEY_INVALID 10001001
#define ERR_ENCRYORDECRY_FAILED 10001002
#define ERR_EVP_INVALID      10001003
#define ERR_SIGNORDESIGN_FAILED 10001004
#define ERR_PARAM_INVALID    10001005

namespace ALG
{
	typedef std::vector<char> BufferArray;

	int64_t ecc_generateKey(std::string &pubKey,std::string &priKey);
	int64_t ecc_sign(const char * priKey, const BufferArray &context, BufferArray & sigBuffer);
	int64_t ecc_verify(const char * pubKey, const BufferArray &context, const BufferArray &sigBuffer);
	int64_t ecc_encryptData(const char * pubKey, const BufferArray &context, BufferArray &sec_buf);
	int64_t ecc_decryptData(const char * priKey, const BufferArray &context, BufferArray &text_buf);
}

#endif

