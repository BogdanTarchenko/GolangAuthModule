package usecase

import (
	"AuthModule/internal/domain/model"
	"AuthModule/internal/domain/repository"
	"AuthModule/internal/domain/usecase"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/bcrypt"
)

type AuthUseCaseImpl struct {
	crypto   usecase.CryptoUseCase
	userRepo repository.UserRepository
}

func NewAuthUseCase(crypto usecase.CryptoUseCase, userRepo repository.UserRepository) *AuthUseCaseImpl {
	return &AuthUseCaseImpl{crypto: crypto, userRepo: userRepo}
}

// Регистрация пользователя: генерация ключей, сохранение их в репозитории
func (a *AuthUseCaseImpl) Register(username, passphrase string) error {
	publicKey, encryptedPrivKey, _, err := a.crypto.GenerateKeyPair(passphrase)
	if err != nil {
		return err
	}

	user := model.User{
		Username:            username,
		PublicKeyPEM:        publicKey,
		EncryptedPrivKeyPEM: encryptedPrivKey,
	}

	return a.userRepo.Save(user)
}

// Аутентификация: проверка passphrase по сохранённому хешу из PEM
func (a *AuthUseCaseImpl) Login(username, passphrase string) (string, string, error) {
	user, err := a.userRepo.FindByUsername(username)
	if err != nil {
		return "", "", err
	}

	ok, err := verifyPassphraseFromPEM(user.EncryptedPrivKeyPEM, passphrase)
	if err != nil || !ok {
		return "", "", errors.New("invalid passphrase")
	}

	return user.PublicKeyPEM, user.EncryptedPrivKeyPEM, nil
}

// Получение информации о пользователе
func (a *AuthUseCaseImpl) GetUser(username string) (model.User, error) {
	return a.userRepo.FindByUsername(username)
}

// Проверка подписи сообщения
func (a *AuthUseCaseImpl) VerifySignature(publicKey string, message []byte, signature []byte) (bool, error) {
	return a.crypto.VerifySignature(publicKey, message, signature)
}

// Вспомогательная функция: извлечение и проверка хеша passphrase из PEM-заголовка
func verifyPassphraseFromPEM(encryptedPrivKeyPEM, passphrase string) (bool, error) {
	block, _ := pem.Decode([]byte(encryptedPrivKeyPEM))
	if block == nil {
		return false, errors.New("invalid PEM block")
	}

	passHashB64 := block.Headers["Passphrase-Hash"]
	if passHashB64 == "" {
		return false, errors.New("no passphrase hash in PEM header")
	}

	hash, err := base64.StdEncoding.DecodeString(passHashB64)
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword(hash, []byte(passphrase))
	return err == nil, nil
}
