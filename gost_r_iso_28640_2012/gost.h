#ifndef GOST_R_ISO_28640_2012
#define GOST_R_ISO_28640_2012

#include "../headers/common.h"

extern int Rand(BYTE *output, DWORD size) {
	HCRYPTPROV hCryptProv;

	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_GOST_2012_256, 0)) {
		PRINT_ERROR("Rand: CryptAcquireContext");
		return -1;
	}

	if (!CryptGenRandom(hCryptProv, size, output)) {
		PRINT_ERROR("Rand: CryptGenRandom");
		return -2;
	}

	CryptReleaseContext(hCryptProv, 0);

	return 0;
}

#endif /* GOST_R_ISO_28640_2012 */
