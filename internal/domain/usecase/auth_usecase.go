package usecase

type AuthUseCase interface {
	Register(username, passphrase string) error
	Login(username, passphrase string) (string, error)
}
