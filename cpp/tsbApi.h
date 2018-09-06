#ifndef __TSB_H_
#define __TSB_H_

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

#define ERR_PUBORPRIKEY_INVALID 10001001
#define ERR_ENCRYORDECRY_FAILED 10001002
#define ERR_EVP_INVALID      10001003
#define ERR_SIGNORDESIGN_FAILED 10001004
#define ERR_PARAM_INVALID    10001005

#define ERR_NAME_INVALID     20001001
#define ERR_PID_INVALID      20001002
#define ERR_CREATEMEM_FAILED 20001003

#define ERR_AES_KEYLENGTH_INVALID 30001001

namespace tsb
{
	typedef enum _CAlg
	{
		TECC = 0,
		TAES256CBC
	}tsbCryptAlgType;

	typedef std::vector<char> BufferArray;
	typedef std::function<long(std::string tid,long code,std::string &key)> KeyCallBack;
	
	class ITSBSDK
	{
	public:
		/*
		tsbGetPubKey
		@description:get object's pub key.
		@param crypt[OUT]:alg type,pubKey[OUT]:pubkey
		@return errcode
		*/
		virtual long tsbGetPubKey(BufferArray &pubKey ) = 0;
		/*
		tsbEncryptData
		@description:encrypt data
		@param crypt[IN] : encrypt alg ,plainText[IN]: plain data,key[IN]:the encrypt key. if the alg type is symmetric alg, the key will used
		,buffer [OUT]: recieve the encrypt data
		@return errcode
		*/
		virtual long tsbEncryptData(tsbCryptAlgType crypt, const BufferArray &key, const BufferArray &plainText, BufferArray & buffer ) = 0;
		/*
		tsbDecryptData
		@description:decrypt data
		@param crypt[IN] : encrypt alg ,secBuffer[IN]: secret data,key[IN]:the encrypt key. if the alg type is symmetric alg, the key will used
		,plainText [OUT]: recieve the plain data
		@return errcode
		*/
		virtual long tsbDecryptData(tsbCryptAlgType crypt, const BufferArray &key, const BufferArray &secBuffer, BufferArray & plainText ) = 0;
		/*
		tsbSignature
		@description:signature for data
		@param context[IN]: be signed data
		,sigBuffer [OUT]: recieve the sign data
		@return errcode
		*/
		virtual long tsbSignature(const BufferArray &context, BufferArray & sigBuffer ) = 0;
		/*
		tsbVerifySignature
		@description:verify signature for data
		@param context[IN]: be signed data
		,sigBuffer [IN]:  sign data
		@return errcode
		*/
		virtual long tsbVerifySignature(const BufferArray &context, const BufferArray &sigBuffer ) = 0;
		/*
		tsbGetBkCFS
		@description:get the cfg back file
		@param safeKey[IN] : safe code ,bkPath[OUT]:back up path
		@return errcode
		*/
		virtual long tsbGetBkCFS(BufferArray &bkPath ) = 0;
		/*
		tsbRestoreCFS
		@description:restore back file for a object
		@param safeKey[IN] : safe code ,tsfsFolder[IN]:cfg folder,bkCFS[IN]: back file
		@return errcode.
		*/
		virtual long tsbRestoreCFS(const char *bkCFS ) = 0;
		/*
		tsbDeleteCFS
		@description:remove object's cfs,when remove a object ,should remove a cfs .
		@param tid[IN] : a uid for cfs,eg:temail
		@return errcode
		*/
		virtual long tsbDeleteCFS() = 0;
	};
	/////////////////////////////////Notice///////////////////////////////
	/////SHOULD CALL setCallBack & setTSBSDKFolder BEFORE INITSDK/////////
	//////////////////////////////////////////////////////////////////////
	/*
	set TSB SDKFolder,
	*/
	long setCallBack(KeyCallBack callBack);
	long setTSBSDKFolder(const char *tsbFolder);
	/*
	init sdk ogject
	*/
	ITSBSDK * initTSBSDK(const char *tid, tsbCryptAlgType alg);
	/*
	un init sdk object
	*/
	void destoryTSBSDK(const char *tid = NULL);
}
#endif