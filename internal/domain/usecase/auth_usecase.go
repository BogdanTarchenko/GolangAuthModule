package usecase

import "AuthModule/internal/domain/model"

type AuthUseCase interface {
	Register(username, passphrase string) error
	Login(username, passphrase string) (publicKeyPEM string, encryptedPrivateKeyPEM string, err error)
	GetUser(username string) (model.User, error)
	VerifySignature(publicKey string, message []byte, signature []byte) (bool, error)
}
