#ifndef GOST_R_34_10_2012_EPH_H
#define GOST_R_34_10_2012_EPH_H

#include "../headers/common.h"

// DESCRIPTION:
// Generate private key in bytes; 
// INPUT:
// prov - type of crypto provider (80 or 81);
// size - pointer to size of the private key in bytes;
// OUTPUT:
// size - size of the private key; 
// BYTE *(GeneratePrivateKey) - pointer to private key bytes;
// BYTE *(GeneratePrivateKey) != NULL if success;
extern BYTE *GeneratePrivateKey(BYTE prov, DWORD *size);

// DESCRIPTION:
// Obtaining private key bytes by
// initialized private key pointer; 
// INPUT:
// hProv - pointer to crypto provider;
// hKey  - pointer to private key;
// size  - size of the private key in bytes; 
// OUTPUT:
// size - size of the private key; 
// BYTE *(BytesPrivateKey) - pointer to private key bytes;
// BYTE *(BytesPrivateKey) != NULL if success;
extern BYTE *BytesPrivateKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, DWORD *size);

// DESCRIPTION:
// Obtaining public key bytes by
// initialized public key pointer; 
// INPUT:
// hKey  - pointer to public key;
// size  - size of the public key in bytes; 
// OUTPUT:
// size - size of the public key; 
// BYTE *(BytesPublicKey) - pointer to public key bytes;
// BYTE *(BytesPublicKey) != NULL if success;
extern BYTE *BytesPublicKey(HCRYPTKEY *hKey, DWORD *size);

// DESCRIPTION:
// Export shared session key by public key of receiver; 
// INPUT:
// hSessionKey  - pointer to session key;
// hPubKey      - pointer to public key;
// size         - pointer to size of the session key in bytes; 
// OUTPUT:
// size - size of the session key; 
// BYTE *(BytesSessionKey) - pointer to session key bytes;
// BYTE *(BytesSessionKey) != NULL if success;
extern BYTE *BytesSessionKey(HCRYPTKEY *hSessionKey, HCRYPTKEY *hPubKey, DWORD *size);

// DESCRIPTION:
// Obtaining a pointer to a private key by
// bytes of the private key; 
// INPUT:
// prov       - type of crypto provider (80 or 81);
// hProv      - pointer to crypto provider;
// hKey       - pointer to private key;
// pkbytes    - private key bytes;
// keyBlobLen - size of the private key in bytes; 
// OUTPUT:
// hKey      - initialized pointer to a private key;
// int (ImportPrivateKey) = 0 if success;
extern int ImportPrivateKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen);

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
// Calculate shared session key by private key of 
// sender(receiver) and public key of receiver(sender); 
// INPUT:
// hProv        - pointer to crypto provider;
// hKey         - pointer to private key;
// pkbytes      - public key bytes;
// keyBlobLen   - size of the public key in bytes; 
// size         - pointer to size of the session key in bytes; 
// OUTPUT:
// size - size of the session key; 
// BYTE *(SharedSessionKey) - pointer to session key bytes;
// BYTE *(SharedSessionKey) != NULL if success;
extern BYTE *SharedSessionKey(HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen, DWORD *size);

#endif /* GOST_R_34_10_2012_EPH_H */
