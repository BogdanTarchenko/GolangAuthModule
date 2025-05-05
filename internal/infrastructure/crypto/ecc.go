package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"math/big"
)

// Структура для хранения подписи в ASN.1 формате
type ecdsaSignature struct {
	R, S *big.Int
}

type ECCCrypto struct{}

func NewECCCrypto() *ECCCrypto {
	return &ECCCrypto{}
}

// Генерация пары ключей и шифрование приватного ключа с использованием passphrase.
// Passphrase хэшируется и сохраняется в заголовке PEM-блока приватного ключа.
func (c *ECCCrypto) GenerateKeyPair(passphrase string) (string, string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", "", err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", "", err
	}

	// Хешируем passphrase (bcrypt используется для хранения в заголовке)
	passHash, err := bcrypt.GenerateFromPassword([]byte(passphrase), bcrypt.DefaultCost)
	if err != nil {
		return "", "", "", err
	}

	// Шифруем приватный ключ (scrypt для получения ключа, XOR для шифрования)
	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		return "", "", "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", "", "", err
	}

	encPriv := xor(privBytes, key)
	encPrivWithSalt := append(salt, encPriv...)
	encPrivB64 := base64.StdEncoding.EncodeToString(encPrivWithSalt)

	// Упаковываем зашифрованный приватный ключ и хеш passphrase в PEM
	privPem := pem.EncodeToMemory(&pem.Block{
		Type: "ENCRYPTED EC PRIVATE KEY",
		Headers: map[string]string{
			"Passphrase-Hash": base64.StdEncoding.EncodeToString(passHash),
		},
		Bytes: []byte(encPrivB64),
	})

	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubBytes,
	})

	return string(pubPem), string(privPem), "", nil
}

// XOR шифрование/дешифрование (простой симметричный способ)
func xor(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// Проверка passphrase с использованием хеша из PEM-заголовка
func (c *ECCCrypto) VerifyPassphrase(passphrase string, passphraseHash string) (bool, error) {
	hash, err := base64.StdEncoding.DecodeString(passphraseHash)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(passphrase))
	return err == nil, nil
}

// Дешифрование приватного ключа с использованием passphrase.
// Проверяет валидность расшифровки через парсинг ключа.
func (c *ECCCrypto) DecryptPrivateKey(encrypted string, passphrase string) (string, error) {
	block, _ := pem.Decode([]byte(encrypted))
	if block == nil {
		return "", errors.New("invalid PEM")
	}

	passHashB64 := block.Headers["Passphrase-Hash"]
	if passHashB64 == "" {
		return "", errors.New("no passphrase hash in PEM")
	}

	encPrivWithSalt, err := base64.StdEncoding.DecodeString(string(block.Bytes))
	if err != nil {
		return "", err
	}
	if len(encPrivWithSalt) < 16 {
		return "", errors.New("invalid encrypted data")
	}

	salt := encPrivWithSalt[:16]
	encPriv := encPrivWithSalt[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	privBytes := xor(encPriv, key)

	// Проверяем корректность приватного ключа
	_, err = x509.ParseECPrivateKey(privBytes)
	if err != nil {
		return "", errors.New("wrong passphrase or corrupted key")
	}

	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})
	return string(privPem), nil
}

// Подписание сообщения приватным ключом
func (c *ECCCrypto) SignMessage(privateKeyPEM string, message []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(message)

	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ecdsaSignature{r, s})
}

// Проверка подписи сообщения
func (c *ECCCrypto) VerifySignature(publicKeyPEM string, message []byte, signature []byte) (bool, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return false, errors.New("invalid PEM")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}

	pub, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("not ECDSA public key")
	}

	var sig ecdsaSignature
	_, err = asn1.Unmarshal(signature, &sig)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(message)
	return ecdsa.Verify(pub, hash[:], sig.R, sig.S), nil
}

// Хеширование passphrase (используется отдельно, если нужно)
func (c *ECCCrypto) HashPassphrase(passphrase string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(passphrase), bcrypt.DefaultCost)
}

// Дополнительный метод шифрования приватного ключа
func (c *ECCCrypto) EncryptPrivateKey(privateKey string, passphrase string) (string, error) {
	privBytes := []byte(privateKey)

	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	encPriv := xor(privBytes, key)
	encPrivWithSalt := append(salt, encPriv...)
	encPrivB64 := base64.StdEncoding.EncodeToString(encPrivWithSalt)

	return encPrivB64, nil
}
