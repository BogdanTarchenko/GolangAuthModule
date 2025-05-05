package usecase

import (
	"AuthModule/internal/infrastructure/crypto"
)

// ECCCryptoAdapter реализует интерфейс CryptoUseCase и делегирует вызовы конкретной реализации ECCCrypto
type ECCCryptoAdapter struct {
	impl *crypto.ECCCrypto
}

func NewECCCryptoAdapter(impl *crypto.ECCCrypto) *ECCCryptoAdapter {
	return &ECCCryptoAdapter{impl: impl}
}

func (a *ECCCryptoAdapter) GenerateKeyPair(passphrase string) (string, string, string, error) {
	return a.impl.GenerateKeyPair(passphrase)
}

func (a *ECCCryptoAdapter) SignMessage(privateKey string, message []byte) ([]byte, error) {
	return a.impl.SignMessage(privateKey, message)
}

func (a *ECCCryptoAdapter) VerifySignature(publicKey string, message []byte, signature []byte) (bool, error) {
	return a.impl.VerifySignature(publicKey, message, signature)
}

func (a *ECCCryptoAdapter) HashPassphrase(passphrase string) ([]byte, error) {
	return a.impl.HashPassphrase(passphrase)
}

func (a *ECCCryptoAdapter) VerifyPassphrase(passphrase string, passphraseHash string) (bool, error) {
	return a.impl.VerifyPassphrase(passphrase, passphraseHash)
}

func (a *ECCCryptoAdapter) EncryptPrivateKey(privateKey string, passphrase string) (string, error) {
	return a.impl.EncryptPrivateKey(privateKey, passphrase)
}

func (a *ECCCryptoAdapter) DecryptPrivateKey(encrypted string, passphrase string) (string, error) {
	return a.impl.DecryptPrivateKey(encrypted, passphrase)
}
