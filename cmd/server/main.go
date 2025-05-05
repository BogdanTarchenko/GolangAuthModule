package main

import (
	_ "AuthModule/docs"
	deliveryhttp "AuthModule/internal/delivery/http"
	"AuthModule/internal/domain/model"
	"AuthModule/internal/infrastructure/crypto"
	"AuthModule/internal/usecase"
	"github.com/swaggo/http-swagger"
	"log"
	"net/http"
	"sync"
)

// In-memory реализация UserRepository
type InMemoryUserRepo struct {
	mu    sync.Mutex
	users map[string]model.User
}

func NewInMemoryUserRepo() *InMemoryUserRepo {
	return &InMemoryUserRepo{
		users: make(map[string]model.User),
	}
}

func (r *InMemoryUserRepo) Save(user model.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user.Username] = user
	return nil
}

func (r *InMemoryUserRepo) FindByUsername(username string) (model.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	user, ok := r.users[username]
	if !ok {
		return model.User{}, ErrUserNotFound
	}
	return user, nil
}

var ErrUserNotFound = &UserNotFoundError{}

type UserNotFoundError struct{}

func (e *UserNotFoundError) Error() string {
	return "user not found"
}

func main() {
	cryptoMod := crypto.NewECCCrypto()                    // Криптомодуль на ECC
	userRepo := NewInMemoryUserRepo()                     // In-memory хранилище пользователей
	authUC := usecase.NewAuthUseCase(cryptoMod, userRepo) // UseCase авторизации
	handler := deliveryhttp.NewHandler(authUC)
	router := deliveryhttp.NewRouter(handler)

	http.Handle("/swagger/", httpSwagger.WrapHandler)
	http.Handle("/", router)

	log.Println("Сервер запущен на :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
