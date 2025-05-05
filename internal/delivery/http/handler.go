package http

import (
	"AuthModule/internal/domain/usecase"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// Запросы и ответы для Swagger и API
type RegisterRequest struct {
	Username   string `json:"username"`
	Passphrase string `json:"passphrase"`
}

type LoginRequest struct {
	Username   string `json:"username"`
	Passphrase string `json:"passphrase"`
}

type LoginResponse struct {
	PublicKeyPEM           string `json:"publicKeyPEM"`
	EncryptedPrivateKeyPEM string `json:"encryptedPrivateKeyPEM"`
}

type AuthzRequest struct {
	Username  string `json:"username"`
	Message   string `json:"message"`
	Signature string `json:"signature"` // base64
}

type AuthzResponse struct {
	Authorized bool   `json:"authorized"`
	Reason     string `json:"reason,omitempty"`
}

type Handler struct {
	AuthUC usecase.AuthUseCase
}

func NewHandler(authUC usecase.AuthUseCase) *Handler {
	return &Handler{AuthUC: authUC}
}

// Register godoc
// @Summary      Регистрация пользователя
// @Description  Регистрирует нового пользователя
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        input  body  RegisterRequest  true  "Данные пользователя"
// @Success      201
// @Failure      400  {string}  string  "invalid request"
// @Failure      500  {string}  string  "internal error"
// @Router       /register [post]
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var body RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := h.AuthUC.Register(body.Username, body.Passphrase); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// Login godoc
// @Summary      Аутентификация пользователя
// @Description  Логин по username и passphrase
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        input  body  LoginRequest  true  "Данные пользователя"
// @Success      200  {object}  LoginResponse
// @Failure      400  {string}  string  "invalid request"
// @Failure      401  {string}  string  "unauthorized"
// @Router       /login [post]
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var body LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	pub, encPriv, err := h.AuthUC.Login(body.Username, body.Passphrase)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(LoginResponse{
		PublicKeyPEM:           pub,
		EncryptedPrivateKeyPEM: encPriv,
	})
}

// Authz godoc
// @Summary      Авторизация по подписи
// @Description  Проверяет подпись сообщения приватным ключом пользователя
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        input  body  AuthzRequest  true  "Данные для авторизации"
// @Success      200  {object}  AuthzResponse
// @Failure      400  {string}  string  "invalid request"
// @Router       /authz [post]
func (h *Handler) Authz(w http.ResponseWriter, r *http.Request) {
	var req AuthzRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	user, err := h.AuthUC.GetUser(req.Username)
	if err != nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "invalid signature encoding", http.StatusBadRequest)
		return
	}
	ok, err := h.AuthUC.VerifySignature(user.PublicKeyPEM, []byte(req.Message), sigBytes)
	if err != nil {
		http.Error(w, "verification error", http.StatusInternalServerError)
		return
	}
	resp := AuthzResponse{
		Authorized: ok,
	}
	if !ok {
		resp.Reason = "invalid signature"
	}
	json.NewEncoder(w).Encode(resp)
}