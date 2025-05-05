package usecase

type CryptoUseCase interface {
	GenerateKeyPair() (publicKey string, privateKey string, err error)
	SignMessage(privateKey string, message []byte) ([]byte, error)
	VerifySignature(publicKey string, message []byte, signature []byte) (bool, error)
}
