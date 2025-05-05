package repository

import (
	"AuthModule/internal/domain/model"
)

type UserRepository interface {
	Save(user model.User) error
	FindByUsername(username string) (model.User, error)
}
