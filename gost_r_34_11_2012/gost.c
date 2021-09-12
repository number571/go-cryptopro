#include "gost.h"

#define HASHSIZE  32
#define BLOCKSIZE 64

extern int NewHash(BYTE prov, HCRYPTPROV *hProv, HCRYPTHASH *hHash) {
    DWORD hashtype;

    switch (prov) {
		case PROV_GOST_2012_256:
			hashtype = CALG_GR3411_2012_256;
		break;
		case PROV_GOST_2012_512:
			hashtype = CALG_GR3411_2012_512;
		break;
	}

    if (!CryptAcquireContext(hProv, NULL, NULL, prov, 0)) {
        PRINT_ERROR("NewHash: CryptAcquireContext");
        return -1;
    }

    if (!CryptCreateHash(*hProv, hashtype, 0, 0, hHash)) {
        PRINT_ERROR("NewHash: CryptCreateHash");
        CryptReleaseContext(*hProv, 0);
        return -2;
    }

    return 0;
}

extern int WriteHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *data, DWORD size) {
    if (!CryptHashData(*hHash, data, size, 0)) {
        PRINT_ERROR("WriteHash: CryptHashData");
        CryptDestroyHash(*hHash);
        CryptReleaseContext(*hProv, 0);
        return -1;
    }

    return 0;
}

extern int ReadHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *rgbHash, DWORD cbHash) {
    if (!CryptGetHashParam(*hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        PRINT_ERROR("ReadHash: CryptGetHashParam");
        CryptDestroyHash(*hHash);
        CryptReleaseContext(*hProv, 0);
        return -1;
    }

    return 0;
}

extern int WriteStateHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *rgbHash, DWORD cbHash) {
    struct _CRYPTOAPI_BLOB data = {cbHash, rgbHash};

    if (!CryptSetHashParam(*hHash, HP_HASHSTATEBLOB, (BYTE *)&data, 0)) {
        PRINT_ERROR("WriteStateHash: CryptSetHashParam");
        CryptDestroyHash(*hHash);
        CryptReleaseContext(*hProv, 0);
        return -1;
    }

    return 0;
}

extern int ReadStateHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *rgbHash, DWORD *cbHash) {
    if (!CryptGetHashParam(*hHash, HP_HASHSTATEBLOB, NULL, cbHash, 0)) {
        PRINT_ERROR("ReadStateHash: CryptGetHashParam (1)");
        CryptDestroyHash(*hHash);
        CryptReleaseContext(*hProv, 0);
        return -1;
    }

    if (!CryptGetHashParam(*hHash, HP_HASHSTATEBLOB, rgbHash, cbHash, 0)) {
        PRINT_ERROR("ReadStateHash: CryptGetHashParam (2)");
        CryptDestroyHash(*hHash);
        CryptReleaseContext(*hProv, 0);
        return -2;
    }

    return 0;
}

extern int CloseHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv) {
    CryptDestroyHash(*hHash);
    CryptReleaseContext(*hProv, 0);

    return 0;
}
