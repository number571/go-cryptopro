#ifndef GOST_R_34_11_2012_H
#define GOST_R_34_11_2012_H

#include "../headers/common.h"

// DESCRIPTION:
// HCRYPTHASH object setting function
// for subsequent hashing of information; 
// INPUT:
// prov  - type of crypto provider (80 or 81);
// hProv - pointer to crypto provider;
// hHash - pointer to HCRYPTHASH object;
// OUTPUT:
// hProv - cryptographic provider = PROV_GOST_2012_256;
// hHash - initialized HCRYPTPROV object;
// int (NewHash) = 0 if success;
extern int NewHash(BYTE prov, HCRYPTPROV *hProv, HCRYPTHASH *hHash);

// DESCRIPTION:
// Partial information hashing function;
// Executed only after the NewHash function,
// when the HCRYPTHASH object has been initialized; 
// INPUT:
// hHash - pointer to HCRYPTHASH object;
// hProv - pointer to crypto provider;
// data  - data to hash;
// size  - size of data;
// OUTPUT:
// hHash - object containing a piece of hashed information;
// int (WriteHash) = 0 if success;
extern int WriteHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *data, DWORD size);

// DESCRIPTION:
// End full hashing function;
// INPUT:
// hHash   - pointer to HCRYPTHASH object;
// hProv   - pointer to crypto provider;
// rgbHash - pointer to byte array;
// cbHash  - size of the hash function result in bytes;
// OUTPUT:
// rgbHash - full hashing result;
// int (ReadHash) = 0 if success;
extern int ReadHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *rgbHash, DWORD cbHash);

// DESCRIPTION:
// Push state of hashing to HCRYPTHASH object;
// INPUT:
// hHash   - pointer to HCRYPTHASH object;
// hProv   - pointer to crypto provider;
// rgbHash - pointer to byte array;
// cbHash  - size of the state;
// OUTPUT:
// hHash   - updated HCRYPTHASH object;
// int (WriteStateHash) = 0 if success;
extern int WriteStateHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *rgbHash, DWORD cbHash);

// DESCRIPTION:
// Read current state of hash;
// INPUT:
// hHash   - pointer to HCRYPTHASH object;
// hProv   - pointer to crypto provider;
// rgbHash - pointer to byte array;
// cbHash  - size of the state;
// OUTPUT:
// rgbHash - state of hashing;
// cbHash  - size of the state;
// int (ReadStateHash) = 0 if success;
extern int ReadStateHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *rgbHash, DWORD *cbHash);

// DESCRIPTION:
// Function for clearing the HCRYPTHASH object and cryptographic provider
// after the end of all actions. Can be performed
// only after the NewHash function, when an object of type
// HCRYPTHASH has been initialized; 
// INPUT:
// hHash - pointer to HCRYPTHASH object;
// hProv - pointer to crypto provider;
// OUTPUT:
// int (CloseHash) = 0 if success;
extern int CloseHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv);

#endif /* GOST_R_34_11_2012_H */
