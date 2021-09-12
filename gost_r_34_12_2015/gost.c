#include "gost.h"

// Размер блока.
#define GR3412SIZ 16

extern int Encrypt(BYTE *data, DWORD dsize, BYTE *key, DWORD ksize, BYTE *iv) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	DWORD mode;
	int len;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, 0)) {
		PRINT_ERROR("Encrypt: CryptAcquireContext");
        return -1;
    }

	if (!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash)) {
		PRINT_ERROR("Encrypt: CryptCreateHash");
		CryptReleaseContext(hProv, 0);
        return -2;
    }

	if (!CryptHashData(hHash, key, ksize, 0)) {
		PRINT_ERROR("Encrypt: CryptHashData");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -3;
    }

	if (!CryptDeriveKey(hProv, CALG_GR3412_2015_K, hHash, CRYPT_EXPORTABLE, &hKey)) {
		PRINT_ERROR("Encrypt: CryptDeriveKey");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -4;
    }

	if(!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
		PRINT_ERROR("Encrypt: CryptSetKeyParam (1)");
		CryptDestroyKey(hKey);
		CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -5;
	}

	mode = CRYPT_MODE_OFB;
	if(!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
		PRINT_ERROR("Encrypt: CryptSetKeyParam (2)");
		CryptDestroyKey(hKey);
		CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -6;
	}

	len = dsize;
	if (!CryptEncrypt(hKey, 0, 1, 0, data, &len, dsize)) {
		CryptDestroyKey(hKey);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return -7;
	}

	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

	return len;
}
