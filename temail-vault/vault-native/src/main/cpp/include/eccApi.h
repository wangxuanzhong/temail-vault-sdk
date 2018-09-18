#ifndef __TSB_ECCAPI_H_
#define __TSB_ECCAPI_H_

#include <vector>
#include <chrono>
#include <functional>

using namespace std;
using namespace std::chrono;

#define ERR_SUCCESS          0
#define ERR_LOGINKEY_INVALID 10000001
#define ERR_TID_INVALID 10000002
#define ERR_CFSFOLDER_INVALID 10000003
#define ERR_CFSFILE_INVALID 10000004
#define ERR_SAFEKEY_INVALID 10000005
#define ERR_FILEENCRY_FAILED 10000006
#define ERR_ALG_INVALID    10000007
#define ERR_TSBFOLDER_DUPFOLDER  10000008
#define ERR_TSBCALLBACK_INVALID 10000009
#define ERR_KEY_INVALID 10000010
#define ERR_IV_INVALID 10000011
#define ERR_SAFETONORMAL_FAILED 10000012
#define ERR_NORMALTOSAFE_FAILED 10000013
#define ERR_RESETPWD_FAILED 10000014
#define ERR_OLDLOGINPWD_INVALID 10000015
#define ERR_MEMORY_FAILED    10000016

#define ERR_PUBORPRIKEY_INVALID 10001001
#define ERR_ENCRYORDECRY_FAILED 10001002
#define ERR_EVP_INVALID      10001003
#define ERR_SIGNORDESIGN_FAILED 10001004
#define ERR_PARAM_INVALID    10001005

#define ERR_NAME_INVALID     20001001
#define ERR_PID_INVALID      20001002
#define ERR_CREATEMEM_FAILED 20001003

#define ERR_AES_KEYLENGTH_INVALID 30001001
#define ERR_EVPINIT_FAILED        30001002
#define ERR_EVPENC_FAILED         30001003
#define ERR_EVPDEC_FAILED         30001004

namespace ECC
{
	typedef std::vector<char> BufferArray;

	long ecc_generateKey(std::string &pubKey,std::string &priKey);
	long ecc_sign(const char * priKey, const BufferArray &context, BufferArray & sigBuffer);
	long ecc_verify(const char * pubKey, const BufferArray &context, const BufferArray &sigBuffer);
	long ecc_encryptData(const char * pubKey, const BufferArray &context, BufferArray &sec_buf);
	long ecc_decryptData(const char * priKey, const BufferArray &context, BufferArray &text_buf);
}

#endif

