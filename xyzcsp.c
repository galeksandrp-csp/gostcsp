#include "gosthash.h"
#include "gost_lcl.h"

static void perevorot_buf(unsigned char *obj, int k)
{
     char buf[64];
     int i;
     for( i = 0; i < k; i++ ) buf[i] = obj[k-1-i];
     memcpy(obj, buf, k);
}

static int pkey_gost01_cp_verify(EC_KEY* pub_key, const unsigned char *sig,
	size_t siglen, unsigned char *tbs, size_t tbs_len)
{
	int ok = 0;
	DSA_SIG *s=unpack_cp_signature(sig,siglen);
	if (!s) return 0;
	if (pub_key) ok = gost2001_do_verify(tbs,tbs_len,s,pub_key);
	DSA_SIG_free(s);
	return ok;
}

int my_verify_gost(char *in_hash, const BYTE *in_sign, char *in_pub1, char *in_pub2, int nid)
{
	int res, errcode;
	EC_KEY *eckey = NULL;
	unsigned char sig[64], tbs[32];
	int siglen=64, tbs_len=32;
	BIGNUM *X=NULL,*Y=NULL;
	char perevorot_pub[32];
	EC_POINT *pub_key;
//Волшебные перевороты
	memcpy(tbs, in_pub1, 32); perevorot_buf(tbs, 32);
	X= getbnfrombuf((const unsigned char*)tbs,32);
	memcpy(tbs, in_pub2, 32); perevorot_buf(tbs, 32);
	Y= getbnfrombuf((const unsigned char*)tbs,32);
	memcpy(tbs, in_hash, 32); //хеш переворачивать не надо! ранее был perevorot_buf(tbs, 32);
	memcpy(sig, in_sign, 64); perevorot_buf(sig, 64);
//Проверка ЭЦП
	if (!(eckey = EC_KEY_new())) { errcode = 1; goto err_exit; }
	if (!fill_GOST2001_params(eckey, nid)) { errcode = 2; goto err_exit; }
	if (!(pub_key = EC_POINT_new(EC_KEY_get0_group(eckey)))) { errcode = 3; goto err_exit; }
	if (!EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(eckey)
			,pub_key,X,Y,NULL)) { errcode = 4; goto err_exit; }
	if (!EC_KEY_set_public_key(eckey,pub_key)) { errcode = 5; goto err_exit; }
	if (!pkey_gost01_cp_verify(eckey, sig, siglen, tbs, tbs_len)) { errcode = 6; goto err_exit; }
	else errcode = 0; //success
err_exit:
	if (pub_key) EC_POINT_free(pub_key);
	if (X) BN_free(X);
	if (Y) BN_free(Y);
	if (eckey) EC_KEY_free(eckey);
	return errcode;
}

void my_hash_gost(const BYTE *buf, int buflen, char *hash_res)
{
	gost_subst_block *b=  &GostR3411_94_CryptoProParamSet;
	gost_hash_ctx ctx;
	init_gost_hash_ctx(&ctx,b);
	start_hash(&ctx);
	hash_block(&ctx,buf,buflen);
	finish_hash(&ctx,(byte *)hash_res);
}

//Глобальные переменные для хеша и публичного ключа
char hash_gost[32];
char hash_sha1[20];
char public_key[64];

BOOL WINAPI
CPAcquireContext(
    OUT HCRYPTPROV *phProv,
    IN  LPCSTR szContainer,
    IN  DWORD dwFlags,
    IN  PVTableProvStruc pVTable)
{
    *phProv = 123;
    return TRUE;
}

BOOL WINAPI
CPHashData(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  DWORD dwFlags)
{
    my_hash_gost(pbData, cbDataLen, hash_gost);
    SHA1(pbData, cbDataLen, hash_sha1);
    return TRUE;
}

BOOL WINAPI
CPGetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
	switch(dwParam)
	{
		case HP_HASHVAL:
			if(*pcbDataLen == 20) // у нас просят отпечаток sha1
			{
				memcpy(pbData, hash_sha1, 20);
				break;
			}
		default:
			*pcbDataLen = 0;
			SetLastError(E_INVALIDARG);
			return FALSE;
	}
    return TRUE;
}

BOOL WINAPI
CPVerifySignature(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbSignature,
    IN  DWORD cbSigLen,
    IN  HCRYPTKEY hPubKey,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags)
{
#define NTE_IC_ERROR_PREDEF          0x89900000L
    INT err;
    err = my_verify_gost(hash_gost, pbSignature, public_key, public_key+32, 
            NID_id_GostR3410_2001_CryptoPro_A_ParamSet);
    if ( err ) 
    {
        SetLastError( NTE_IC_ERROR_PREDEF | err );
        return FALSE;
    }
    return TRUE;
}

BOOL WINAPI xyz_ConvertPublicKeyInfo(
  DWORD dwCertEncodingType,
  VOID *EncodedKeyInfo,
  DWORD dwAlg,
  DWORD dwFlags,
  BYTE** ppStructInfo,
  DWORD* StructLen
)
{
    memcpy(public_key, ((CERT_PUBLIC_KEY_INFO*)EncodedKeyInfo)->PublicKey.pbData + 2, 64);
    return TRUE;
}
