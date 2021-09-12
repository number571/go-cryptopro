#ifndef GOST_R_ISO_28640_2012_H
#define GOST_R_ISO_28640_2012_H

#include "../headers/common.h"

// DESCRIPTION:
// Generate function cryptographically strong
// sequences of pseudo-random bytes; 
// INPUT:
// output - pointer to byte array;
// size   - the number of bytes written to the output;
// OUTPUT:
// output - filled array with pseudo-random bytes;
// int (Rand) = 0 if success;
extern int Rand(BYTE *output, DWORD size);

#endif /* GOST_R_ISO_28640_2012_H */
