#ifndef GOST_R_34_12_2015_H
#define GOST_R_34_12_2015_H

#include "../headers/common.h"

// DESCRIPTION:
// Encryption / decryption function;
// GOST R 34.12-2015;
// Encryption mode = Output Feed Back (OFB);
// The key is passed through the
// hash function GOST R 34.11-2012; 
// INPUT:
// data  - initial data for encryption / decryption;
// dsize - size of original data in bytes;
// key   - encryption key;
// ksize - encryption key size in bytes;
// iv    - initialization vector = 16 bytes;
// OUTPUT:
// data - encrypted / decrypted data ;
// int (Cipher) = 0 if success;
extern int Encrypt(BYTE *data, DWORD dsize, BYTE *key, DWORD ksize, BYTE *iv);

#endif /* GOST_R_34_12_2015_H */
