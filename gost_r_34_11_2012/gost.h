#ifndef GOST_R_34_11_2012
#define GOST_R_34_11_2012

#include "../headers/common.h"

extern int NewHash(HCRYPTPROV *hProv, HCRYPTHASH *hHash) {
	if (!CryptAcquireContext(hProv, NULL, NULL, PROV_GOST_2012_256, 0)) {
		PRINT_ERROR("NewHash: CryptAcquireContext");
		return -1;
	}

	if (!CryptCreateHash(*hProv, CALG_GR3411_2012_256, 0, 0, hHash)) {
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

extern int CloseHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv) {
	CryptDestroyHash(*hHash);
	CryptReleaseContext(*hProv, 0);

	return 0;
}

#endif /* GOST_R_34_11_2012 */
