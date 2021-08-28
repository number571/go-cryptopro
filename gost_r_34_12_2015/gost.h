#ifndef GOST_R_34_12_2015
#define GOST_R_34_12_2015

#include "../headers/common.h"

#define GR3412SIZ 16
#define ENCRYPT    1
#define DECRYPT   -1

extern int Cipher(int opt, BYTE *data, DWORD dsize, BYTE *key, DWORD ksize, BYTE *iv) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	DWORD mode;
	int len;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, 0)) {
		PRINT_ERROR("Cipher: CryptAcquireContext");
        return -1;
    }

	if (!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash)) {
		PRINT_ERROR("Cipher: CryptCreateHash");
		CryptReleaseContext(hProv, 0);
        return -2;
    }

	if (!CryptHashData(hHash, key, ksize, 0)) {
		PRINT_ERROR("Cipher: CryptHashData");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -3;
    }

	if (!CryptDeriveKey(hProv, CALG_GR3412_2015_K, hHash, CRYPT_EXPORTABLE, &hKey)) {
		PRINT_ERROR("Cipher: CryptDeriveKey");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -4;
    }

	if(!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
		PRINT_ERROR("Cipher: CryptSetKeyParam (1)");
		CryptDestroyKey(hKey);
		CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -5;
	}

	mode = CRYPT_MODE_CBC;
	if(!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
		PRINT_ERROR("Cipher: CryptSetKeyParam (2)");
		CryptDestroyKey(hKey);
		CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -6;
	}

	switch(opt) {
	case ENCRYPT:
		len = dsize - GR3412SIZ;
		if (!CryptEncrypt(hKey, 0, 1, 0, data, &len, dsize)) {
			PRINT_ERROR("Cipher: CryptEncrypt");
			CryptDestroyKey(hKey);
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			return -7;
		}
		break;
	case DECRYPT:
		len = dsize;
		if (!CryptDecrypt(hKey, 0, 1, 0, data, &len)) {
			PRINT_ERROR("Cipher: CryptDecrypt");
			CryptDestroyKey(hKey);
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			return -8;
		}
		break;
	}

	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

	return len;
}

#endif /* GOST_R_34_12_2015 */
