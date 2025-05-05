package http

import (
	"net/http"
)

func NewRouter(handler *Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", handler.Register) // Регистрация
	mux.HandleFunc("/login", handler.Login)       // Логин
	mux.HandleFunc("/authz", handler.Authz)       // Авторизация по подписи
	return mux
}
