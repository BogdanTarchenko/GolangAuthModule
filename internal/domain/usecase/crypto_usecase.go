package usecase

type CryptoUseCase interface {
	GenerateKeyPair(passphrase string) (publicKey string, encryptedPrivateKey string, passphraseHash string, err error)
	SignMessage(privateKey string, message []byte) ([]byte, error)
	VerifySignature(publicKey string, message []byte, signature []byte) (bool, error)
	HashPassphrase(passphrase string) ([]byte, error)
	VerifyPassphrase(passphrase string, passphraseHash string) (bool, error)
	EncryptPrivateKey(privateKey string, passphrase string) (string, error)
	DecryptPrivateKey(encrypted string, passphrase string) (string, error)
}
