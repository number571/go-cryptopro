#ifndef GOST_R_34_10_2012_H
#define GOST_R_34_10_2012_H

#include "../headers/common.h"

// DESCRIPTION:
// Create container wirh key by name and password;
// INPUT:
// prov      - type of crypto provider (80 or 81);
// container - container name;
// password  - password of container;
// OUTPUT:
// int (CreateContainer) = 0 if success;
// int (CreateContainer) = 1 if container exist;
extern int CreateContainer(BYTE prov, BYTE *container, BYTE *password);

// DESCRIPTION:
// Obtaining a pointer to a public key by
// container name; 
// INPUT:
// prov      - type of crypto provider (80 or 81);
// hProv     - pointer to crypto provider;
// hKey      - pointer to public key;
// container - container name;
// password  - password of container;
// OUTPUT:
// hKey      - initialized pointer to a public key;
// int (OpenContainer) = 0 if success;
extern int OpenContainer(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *container, BYTE *password);

// DESCRIPTION:
// Function for checking the existence of a private key 
// by container name and password;
// INPUT:
// prov      - type of crypto provider (80 or 81);
// container - container name;
// password  - password of container;
// OUTPUT:
// int (CheckContainer) = 0 if success;
extern int CheckContainer(BYTE prov, BYTE *container, BYTE *password);

// DESCRIPTION:
// Function of signing information with a private key;
// GOST R 34.10-2012 (256, 512).
// The private key is taken from the container using a password;
// The data to be signed goes first via hash function GOST R 34.11-2012; 
// INPUT:
// prov      - type of crypto provider (80 or 81);
// container - container name;
// password  - password of container;
// data      - data to be signed;
// size      - size of data;
// dwSigLen  - pointer to the size of the signature in bytes;
// OUTPUT:
// dwSigLen  - size of signature;
// BYTE *(CheckPrivateKey) - pointer to digital signature ;
// BYTE *(CheckPrivateKey) != NULL if success;
extern BYTE *SignMessage(BYTE prov, BYTE *container, BYTE *password, BYTE *data, DWORD size, DWORD *dwSigLen);

// DESCRIPTION:
// Signature verification function based on source data; 
// INPUT:
// prov      - type of crypto provider (80 or 81);
// hKey      - pointer to public key;
// sign      - digital signature ;
// dwSigLen  - size of signature in bytes;
// data      - data subject to signature verification;
// size      - the size of the data in bytes;
// OUTPUT:
// int (VerifySign) = 0 signature is correct (successful completion);
// int (VerifySign) = 1 signature is incorrect (successful completion) ;
// int (VerifySign) < 0 result with error;
extern int VerifySign(BYTE prov, HCRYPTKEY *hKey, BYTE *sign, DWORD dwSigLen, BYTE *data, DWORD size);

// DESCRIPTION:
// Obtaining a pointer to a public key by
// bytes of the public key; 
// INPUT:
// prov       - type of crypto provider (80 or 81);
// hProv      - pointer to crypto provider;
// hKey       - pointer to public key;
// pkbytes    - public key bytes;
// keyBlobLen - size of the public key in bytes; 
// OUTPUT:
// hKey      - initialized pointer to a public key;
// int (ImportPublicKey) = 0 if success;
extern int ImportPublicKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen);

// DESCRIPTION:
// Obtaining public key bytes by
// initialized public key pointer; 
// INPUT:
// hKey - pointer to public key;
// size - size of the public key in bytes; 
// OUTPUT:
// size - size of the public key; 
// BYTE *(BytesPublicKey) - pointer to public key bytes;
// BYTE *(BytesPublicKey) != NULL if success;
extern BYTE *BytesPublicKey(HCRYPTKEY *hKey, DWORD *size);

#endif /* GOST_R_34_10_2012_H */
