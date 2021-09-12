#include "gost.h"

extern BYTE *GeneratePrivateKey(BYTE prov, DWORD *size) {
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	ALG_ID alg;
	BYTE *output;

	switch (prov) {
		case PROV_GOST_2012_256:
			alg = CALG_DH_GR3410_12_256_EPHEM;
		break;
		case PROV_GOST_2012_512:
			alg = CALG_DH_GR3410_12_512_EPHEM;
		break;
	}

	if (!CryptAcquireContext(&hProv, NULL, NULL, prov, 0)) {
		PRINT_ERROR("GeneratePrivateKey: CryptAcquireContext");
		return NULL;
	}

	if (!CryptGenKey(hProv, alg, CRYPT_EXPORTABLE, &hKey)) {
		PRINT_ERROR("GeneratePrivateKey: CryptGenKey");
		CryptReleaseContext(hProv, 0);
		return NULL;
	}

	output = BytesPrivateKey(prov, &hProv, &hKey, size);

	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);

	return output;
}

extern BYTE *BytesPrivateKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, DWORD *size) {
	HCRYPTKEY hDerivedKey;
	HCRYPTHASH hHash;
	DWORD hashtype;
	BYTE *pkbytes;

    switch (prov) {
		case PROV_GOST_2012_256:
			hashtype = CALG_GR3411_2012_256;
		break;
		case PROV_GOST_2012_512:
			hashtype = CALG_GR3411_2012_512;
		break;
	}

	if (!CryptCreateHash(*hProv, hashtype, 0, 0, &hHash)){
        PRINT_ERROR("BytesPrivateKey: CryptCreateHash");
		CryptDestroyKey(*hKey);
		CryptReleaseContext(*hProv, 0);
        return NULL;
    }

	if(!CryptDeriveKey(*hProv, CALG_UECSYMMETRIC_EPHEM, hHash, 0, &hDerivedKey)) {
        PRINT_ERROR("BytesPrivateKey: CryptDeriveKey");
		CryptDestroyHash(hHash);
		CryptDestroyKey(*hKey);
		CryptReleaseContext(*hProv, 0);
        return NULL;
    }

	if(!CryptExportKey(*hKey, hDerivedKey, PRIVATEKEYBLOB, 0, NULL, size)) {
		PRINT_ERROR("BytesPrivateKey: CryptExportKey (1)");
		CryptDestroyKey(hDerivedKey);
		CryptDestroyHash(hHash);
		CryptDestroyKey(*hKey);
		CryptReleaseContext(*hProv, 0);
        return NULL;
    }

	pkbytes = (BYTE*)malloc(sizeof(BYTE)*(*size));

	if(!CryptExportKey(*hKey, hDerivedKey, PRIVATEKEYBLOB, 0, pkbytes, size)) {
		PRINT_ERROR("BytesPrivateKey: CryptExportKey (2)");
		free(pkbytes);
		CryptDestroyKey(hDerivedKey);
		CryptDestroyHash(hHash);
		CryptDestroyKey(*hKey);
		CryptReleaseContext(*hProv, 0);
        return NULL;
    }

	return pkbytes;
}

extern BYTE *BytesPublicKey(HCRYPTKEY *hKey, DWORD *size) {
	BYTE *pkbytes;

	if(!CryptExportKey(*hKey, 0, PUBLICKEYBLOB, 0, NULL, size)) {
		PRINT_ERROR("BytesPublicKey: CryptExportKey (1)");
		CryptDestroyKey(*hKey);
        return NULL;
    }

	pkbytes = (BYTE*)malloc(sizeof(BYTE)*(*size));

	if(!CryptExportKey(*hKey, 0, PUBLICKEYBLOB, 0, pkbytes, size)) {
		PRINT_ERROR("BytesPublicKey: CryptExportKey (2)");
		free(pkbytes);
		CryptDestroyKey(*hKey);
        return NULL;
    }

	return pkbytes;
}

extern BYTE *BytesSessionKey(HCRYPTKEY *hSessionKey, HCRYPTKEY *hPubKey, DWORD *size) {
	BYTE *pkbytes;

	if(!CryptExportKey(*hSessionKey, *hPubKey, SIMPLEBLOB, 0, NULL, size)) {
		PRINT_ERROR("BytesSessionKey: CryptExportKey (1)");
		CryptDestroyKey(*hSessionKey);
		CryptDestroyKey(*hPubKey);
        return NULL;
    }

	pkbytes = (BYTE*)malloc(sizeof(BYTE)*(*size));

	if(!CryptExportKey(*hSessionKey, *hPubKey, SIMPLEBLOB, 0, pkbytes, size)) {
		PRINT_ERROR("BytesSessionKey: CryptExportKey (2)");
		free(pkbytes);
		CryptDestroyKey(*hSessionKey);
		CryptDestroyKey(*hPubKey);
        return NULL;
    }

	return pkbytes;
}

extern int ImportPrivateKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen) {
	DWORD hashtype;
	HCRYPTHASH hHash;
	HCRYPTKEY hDerivedKey;

	switch (prov) {
		case PROV_GOST_2012_256:
			hashtype = CALG_GR3411_2012_256;
		break;
		case PROV_GOST_2012_512:
			hashtype = CALG_GR3411_2012_512;
		break;
	}

	if (!CryptAcquireContext(hProv, NULL, NULL, prov, 0)) {
		PRINT_ERROR("ImportPrivateKey: CryptAcquireContext");
		return -1;
	}

	if (!CryptCreateHash(*hProv, hashtype, 0, 0, &hHash)) {
        PRINT_ERROR("ImportPrivateKey: CryptCreateHash");
		CryptReleaseContext(*hProv, 0);
        return -2;
    }

	if(!CryptDeriveKey(*hProv, CALG_UECSYMMETRIC_EPHEM, hHash, 0, &hDerivedKey)) {
        PRINT_ERROR("ImportPrivateKey: CryptDeriveKey");
		CryptDestroyHash(hHash);
		CryptReleaseContext(*hProv, 0);
        return -3;
    }

	if (!CryptImportKey(*hProv, pkbytes, keyBlobLen, hDerivedKey, 0, hKey)) {
		PRINT_ERROR("ImportPrivateKey: CryptImportKey");
		CryptDestroyKey(hDerivedKey);
		CryptDestroyHash(hHash);
		CryptReleaseContext(*hProv, 0);
		return -4;
	}

	CryptDestroyHash(hHash);

	return 0;
}

extern int ImportPublicKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen) {
	if (!CryptAcquireContext(hProv, NULL, NULL, prov, 0)) {
		PRINT_ERROR("ImportPublicKey: CryptAcquireContext");
		return -1;
	}

	if (!CryptImportKey(*hProv, pkbytes, keyBlobLen, 0, 0, hKey)) {
		PRINT_ERROR("ImportPublicKey: CryptImportKey");
		CryptReleaseContext(*hProv, 0);
		return -2;
	}

	return 0;
}

extern BYTE *SharedSessionKey(HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen, DWORD *size) {
	const int IVSIZ = 16;

	HCRYPTKEY hSessionKey;
	HCRYPTHASH hHash;
	HCRYPTKEY hPubKey;
	
	BYTE iv[IVSIZ];
	DWORD alg;
	DWORD mode;

	BYTE *result;

	if (!CryptCreateHash(*hProv, CALG_GR3411_2012_256, 0, 0, &hHash)) {
		PRINT_ERROR("SharedSessionKey: CryptCreateHash");
		CryptDestroyKey(*hKey);
		CryptReleaseContext(*hProv, 0);
        return NULL;
    }

	if (!CryptHashData(hHash, NULL, 0, 0)) {
		PRINT_ERROR("SharedSessionKey: CryptHashData");
        CryptDestroyHash(hHash);
		CryptDestroyKey(*hKey);
        CryptReleaseContext(*hProv, 0);
        return NULL;
    }

	if (!CryptDeriveKey(*hProv, CALG_GR3412_2015_K, hHash, CRYPT_EXPORTABLE, &hSessionKey)) {
		PRINT_ERROR("SharedSessionKey: CryptDeriveKey");
        CryptDestroyHash(hHash);
		CryptDestroyKey(*hKey);
        CryptReleaseContext(*hProv, 0);
        return NULL;
    }

    if(!CryptImportKey(*hProv, pkbytes, keyBlobLen, *hKey, 0, &hPubKey)) {
        PRINT_ERROR("SharedSessionKey: CryptImportKey");
		CryptDestroyKey(hSessionKey);
		CryptDestroyHash(hHash);
		CryptDestroyKey(*hKey);
		CryptReleaseContext(*hProv, 0);
		return NULL;
    }

	alg = CALG_PRO12_EXPORT;
	if(!CryptSetKeyParam(hPubKey, KP_ALGID, (BYTE*)&alg, 0)) {
        PRINT_ERROR("SharedSessionKey: CryptSetKeyParam");
		CryptDestroyKey(hSessionKey);
		CryptDestroyKey(hPubKey);
		CryptDestroyHash(hHash);
		CryptDestroyKey(*hKey);
		CryptReleaseContext(*hProv, 0);
		return NULL;
    }

	memset(iv, 0, IVSIZ);
	if(!CryptSetKeyParam(hPubKey, KP_IV, iv, 0)) {
		PRINT_ERROR("SharedSessionKey: CryptSetKeyParam (1)");
		CryptDestroyKey(hSessionKey);
		CryptDestroyKey(hPubKey);
		CryptDestroyHash(hHash);
		CryptDestroyKey(*hKey);
		CryptReleaseContext(*hProv, 0);
        return NULL;
	}

	mode = CRYPT_MODE_CBC;
	if(!CryptSetKeyParam(hPubKey, KP_MODE, (BYTE*)&mode, 0)) {
		PRINT_ERROR("SharedSessionKey: CryptSetKeyParam (2)");
		CryptDestroyKey(hSessionKey);
		CryptDestroyKey(hPubKey);
		CryptDestroyHash(hHash);
		CryptDestroyKey(*hKey);
		CryptReleaseContext(*hProv, 0);
        return NULL;
	}

	CryptDestroyHash(hHash);

	result = BytesSessionKey(&hSessionKey, &hPubKey, size);

	CryptDestroyKey(hSessionKey);
	CryptDestroyKey(hPubKey);

	return result;
}
