package usecase

import (
	"AuthModule/internal/domain/model"
	"AuthModule/internal/domain/repository"
	"AuthModule/internal/domain/usecase"
)

type AuthUseCaseImpl struct {
	userRepo repository.UserRepository
	crypto   usecase.CryptoUseCase
}

func NewAuthUseCase(userRepo repository.UserRepository, crypto usecase.CryptoUseCase) *AuthUseCaseImpl {
	return &AuthUseCaseImpl{
		userRepo: userRepo,
		crypto:   crypto,
	}
}

func (a *AuthUseCaseImpl) Register(username, passphrase string) error {
	publicKey, _, err := a.crypto.GenerateKeyPair()
	if err != nil {
		return err
	}

	user := model.User{
		Username:     username,
		PublicKeyPEM: publicKey,
	}

	return a.userRepo.Save(user)
}

func (a *AuthUseCaseImpl) Login(username, passphrase string) (string, error) {
	user, err := a.userRepo.FindByUsername(username)
	if err != nil {
		return "", err
	}

	return user.PublicKeyPEM, nil
}
