# Go КриптоПро
> Интерфейсы адаптированы под ядро Tendermint
> https://github.com/tendermint/tendermint

### Реализация
* ГОСТ Р 34.10-2012 (ЭЦП, ЭК)
* ГОСТ Р 34.11-2012 (Хеширование)
* ГОСТ Р 34.12-2015 (Шифрование)
* ГОСТ Р ИСО 28640-2012 (КСГПСЧ)

### Установка
1. Скачать CSP 5.0 https://www.cryptopro.ru/products/csp/downloads
2. Разархивировать и установить командой `./install.sh`
3. Скачать `git clone github.org/Number571/go-cryptopro`
4. Запустить `go run main.go`

### ГОСТ Р 34.10-2012 (ЭЦП)

##### Интерфейсные функции Go
```go
func GenPrivKey(cfg *Config) error {}
func NewPrivKey(cfg *Config) (PrivKey, error) {}
func LoadPrivKey(pbytes []byte) (PrivKey, error) {}
func (key PrivKey) Bytes() []byte {}
func (key PrivKey) String() string {}
func (key PrivKey) Sign(dbytes []byte) ([]byte, error) {}
func (key PrivKey) PubKey() PubKey {}
func (key PrivKey) Equals(cmp PrivKey) bool {}
func (key PrivKey) Type() string {}

func LoadPubKey(pbytes []byte) (PubKey, error) {}
func (key PubKey) Address() Address {}
func (key PubKey) Bytes() []byte {}
func (key PubKey) String() string {}
func (key PubKey) VerifySignature(dbytes, sign []byte) bool {}
func (key PubKey) Equals(cmp PubKey) bool {}
func (key PubKey) Type() string {}

func NewBatchVerifier() BatchVerifier {}
func (b *BatchVerifier) Add(key PubKey, message, signature []byte) error {}
func (b *BatchVerifier) Verify() (bool, []bool) {}

func NewConfig(prov ProvType, subject, password string) *Config {}
```

##### Интерфейсные функции Си
```c
extern int CreateContainer(BYTE prov, BYTE *container, BYTE *password);
extern int CheckPrivateKey(BYTE prov, BYTE *container, BYTE *password);
extern BYTE *SignMessage(BYTE prov, BYTE *container, BYTE *password, BYTE *data, DWORD size, DWORD *dwSigLen);
extern int VerifySign(BYTE prov, HCRYPTKEY *hKey, BYTE *sign, DWORD dwSigLen, BYTE *data, DWORD size);
extern int HcryptKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *container);
extern int ImportPublicKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen);
extern BYTE *BytesPublicKey(HCRYPTKEY *hKey, DWORD *size);
```

##### Пример использования
```go
package main

import (
	"fmt"

	gkeys "github.org/number571/go-cryptopro/gost_r_34_10_2012"
)

func main() {
	cfg := gkeys.NewConfig(gkeys.K256, "username", "password")

	err := gkeys.GenPrivKey(cfg)
	if err != nil {
		fmt.Println("Warning: key already exist?")
	}

	priv, err := gkeys.NewPrivKey(cfg)
	if err != nil {
		panic(err)
	}

	pub := priv.PubKey()
	pbytes := pub.Bytes()

	msg := []byte("hello, world!")
	sign, err := priv.Sign(msg)
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"Type: %s;\nPubKey [%dB]: %x;\nSign [%dB]: %x;\nSuccess: %t;\n",
		pub.Type(),
		len(pbytes),
		pbytes,
		len(sign),
		sign,
		pub.VerifySignature(msg, sign),
	)
}
```

##### Пример вывода
```
Warning: key already exist?
Type: ГОСТ Р 34.10-2012 256;
PubKey [102B]: 5006200000492e00004d41473100020000301306072a85030202230106082a850307010102022f6197366b7cd9fb002ec3b7b8ab066fed6a514617a01c6a3ea5124b6acde80fbdb3004940753e0bb350e3f08f9a778dc87b14836a7d7ecf0ec53e49ccdce28e;
Sign [64B]: d8c136c454da21069a7a7064b8fc6c7034b688a7edd0f0bef65d0cbb83ec851ab55b3ae46b6b344a989880d2563f93a47183bb434c65362590b68f03ef6c8ae2;
Success: true;
```

### ГОСТ Р 34.10-2012 (ЭК)

##### Интерфейсные функции Go
```go
func NewPrivKey(cfg *Config) (PrivKey, error) {}
func LoadPrivKey(pbytes []byte) (PrivKey, error) {}
func (key PrivKey) Bytes() []byte {}
func (key PrivKey) String() string {}
func (key PrivKey256) Secret(pub PubKey) []byte {}
func (key PrivKey) PubKey() PubKey {}
func (key PrivKey) Equals(cmp PrivKey) bool {}
func (key PrivKey) Type() string {}

func LoadPubKey(pbytes []byte) (PubKey, error) {}
func (key PubKey) Address() Address {}
func (key PubKey) Bytes() []byte {}
func (key PubKey) String() string {}
func (key PubKey) Equals(cmp PubKey) bool {}
func (key PubKey) Type() string {}
```

##### Интерфейсные функции Си
```c
extern BYTE *GeneratePrivateKey(BYTE prov, DWORD *size);
extern BYTE *BytesPrivateKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, DWORD *size);
extern BYTE *BytesPublicKey(HCRYPTPROV *hProv, HCRYPTKEY *hKey, DWORD *size);
extern BYTE *BytesSessionKey(HCRYPTPROV *hProv, HCRYPTKEY *hSessionKey, HCRYPTKEY *hPubKey, DWORD *size);
extern int ImportPrivateKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen);
extern int ImportPublicKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen);
extern BYTE *SharedSessionKey(HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen, DWORD *size);
```

##### Пример использования
```go
package main

import (
	"bytes"
	"fmt"

	gkeys "github.org/number571/go-cryptopro/gost_r_34_10_2012_eph"
)

func main() {
	priv1, err := gkeys.NewPrivKey(gkeys.K256)
	if err != nil {
		panic(err)
	}
	priv2, err := gkeys.NewPrivKey(gkeys.K256)
	if err != nil {
		panic(err)
	}

	xchkey1 := priv1.Secret(priv2.PubKey())
	xchkey2 := priv2.Secret(priv1.PubKey())

	fmt.Printf("Xchkey1: %X;\nXchkey2: %X;\nSuccess: %t;\n",
		xchkey1,
		xchkey2,
		bytes.Equal(xchkey1, xchkey2),
	)
}
```

##### Пример вывода
```
Xchkey1: A3241280FD2ABBCFEF1D3CEA19FE03291F2EC9441E5C44D8109432ED05345566;
Xchkey2: A3241280FD2ABBCFEF1D3CEA19FE03291F2EC9441E5C44D8109432ED05345566;
Success: true;
```

### ГОСТ Р 34.11-2012

##### Интерфейсные функции Go
```go
func New(prov ProvType) Hash {}
func (hasher *Hash) Write(p []byte) (n int, err error) {}
func (hasher *Hash) Sum(p []byte) []byte {}
func (hasher *Hash) Reset() {}
func (hasher *Hash) Size() int {}
func (hasher *Hash) BlockSize() int {}
func (hasher *Hash) Type() string {}
func (hasher *Hash) DoubleSum(p []byte) []byte {}

func Sum(prov ProvType, data []byte) []byte {}
func NewHMAC(prov ProvType, key []byte) Hash {}
func SumHMAC(prov ProvType, key, data []byte) []byte {}
```

##### Интерфейсные функции Си
```c
extern int NewHash(BYTE prov, HCRYPTPROV *hProv, HCRYPTHASH *hHash);
extern int WriteHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *data, DWORD size);
extern int ReadHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *rgbHash, DWORD cbHash);
extern int WriteStateHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *rgbHash, DWORD cbHash);
extern int ReadStateHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv, BYTE *rgbHash, DWORD *cbHash);
extern int CloseHash(HCRYPTHASH *hHash, HCRYPTPROV *hProv);
```

##### Пример использования 
```go
package main

import (
	"encoding/hex"
	"fmt"

	ghash "github.org/number571/go-cryptopro/gost_r_34_11_2012"
)

func main() {
	msg1 := []byte("aaa")
	msg2 := []byte("bbb")
	msg3 := []byte("aaabbb")

	hasher := ghash.New(ghash.H256)
	hasher.Write(msg3)
	fmt.Println(hex.EncodeToString(hasher.Sum(nil)))

	hasher = ghash.New(ghash.H256)
	hasher.Write(msg1)
	hasher.Write(msg2)
	fmt.Println(hex.EncodeToString(hasher.Sum(nil)))

	fmt.Println(hex.EncodeToString(hasher.Sum(msg3)))

	data := ghash.Sum256(msg3)
	fmt.Println(hex.EncodeToString(data))

	hasher = ghash.New(ghash.H256)
	hasher.Write(data)
	hasher.Write(msg1)
	hasher.Write(msg2)
	fmt.Println(hex.EncodeToString(hasher.Sum(nil)))
}
```

##### Пример вывода
```
2e3cbeb240b4b8d1e2dc8610faff9e5bee23f95bb04c18d999034487dbecb490
2e3cbeb240b4b8d1e2dc8610faff9e5bee23f95bb04c18d999034487dbecb490
c15f2f30197026209e2f9a3f6e8276594ed1496bba115c2421bad2a18fb58cd1
2e3cbeb240b4b8d1e2dc8610faff9e5bee23f95bb04c18d999034487dbecb490
7c8ae9a518d240d6174a18c861db7b46856de3d146766bda4447edeaf7e2ad0c
```

### ГОСТ Р 34.12-2015

##### Интерфейсные функции Go
```go
func New(key []byte) (cipher.AEAD, error) {}
func (aead *AEAD) Seal(dst, nonce, plaintext, addData []byte) []byte {}
func (aead *AEAD) Open(dst, nonce, ciphertext, addData []byte) ([]byte, error) {}
func (aead *AEAD) NonceSize() int {}
func (aead *AEAD) Overhead() int {}
```

##### Интерфейсные функции Си
```c
extern int Encrypt(BYTE *data, DWORD dsize, BYTE *key, DWORD ksize, BYTE *iv);
```

##### Пример использования 
```go
package main

import (
	"bytes"
	"fmt"

	gcipher "github.org/number571/go-cryptopro/gost_r_34_12_2015"
)

func main() {
	var (
		openData = []byte("hello")
		mainData = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		key      = []byte("qwertyuiopasdfghjklzxcvbnm123456")
		nonce    = []byte("1234567890123456")
	)

	fmt.Println(mainData)

	cphr, err := gcipher.New(key)
	if err != nil {
		panic(err)
	}

	enc := cphr.Seal(nil, nonce, mainData, openData)
	fmt.Println(enc)

	dec, err := cphr.Open(nil, nonce, enc, openData)
	fmt.Println(dec, err)

	fmt.Println(bytes.Equal(mainData, dec))
}
```

##### Пример вывода
```
[65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90]
[30 138 37 40 172 162 214 203 167 13 158 58 182 210 53 248 8 91 10 31 7 40 217 234 154 152 205 146 154 232 110 244 21 178 32 20 138 162 66 238 18 82 18 225 247 177 110 149]
[65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90]
true
```

### ГОСТ Р ИСО 28640-2012

##### Интерфейсные функции Go
```go
func Read(p []byte) (int, error) {}
func (r Reader) Read(p []byte) (int, error) {}
func Rand(size int) []byte {}
```

##### Интерфейсные функции Си
```c
extern int Rand(BYTE *output, DWORD size);
```

##### Пример использования
```go
package main

import (
	"fmt"

	grand "github.org/number571/go-cryptopro/gost_r_iso_28640_2012"
)

func main() {
	data := make([]byte, 16)
	grand.Read(data)

	fmt.Println(data)
	fmt.Println(grand.Rand(32))
}
```

##### Пример вывода
```
[55 152 51 118 11 127 137 228 120 143 40 127 148 11 7 96]
[19 244 168 91 189 93 232 8 18 69 164 81 69 248 120 139 166 161 45 137 121 208 61 33 91 7 178 166 45 213 68 196]
```
