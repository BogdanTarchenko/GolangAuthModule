package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"AuthModule/internal/infrastructure/crypto"
)

func main() {
	username := "alice"
	passphrase := "mySecretPassphrase"
	message := "hello, world!"

	// Регистрация пользователя
	registerBody := map[string]string{
		"username":   username,
		"passphrase": passphrase,
	}
	registerData, _ := json.Marshal(registerBody)
	resp, err := http.Post("http://localhost:8080/register", "application/json", bytes.NewReader(registerData))
	if err != nil {
		fmt.Println("Ошибка регистрации:", err)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("Ошибка регистрации:", string(body))
		os.Exit(1)
	}
	fmt.Println("Регистрация успешна!")

	// Логин пользователя
	loginBody := map[string]string{
		"username":   username,
		"passphrase": passphrase,
	}
	loginData, _ := json.Marshal(loginBody)
	resp, err = http.Post("http://localhost:8080/login", "application/json", bytes.NewReader(loginData))
	if err != nil {
		fmt.Println("Ошибка логина:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("Ошибка логина:", string(body))
		os.Exit(1)
	}
	var loginResp struct {
		PublicKeyPEM           string `json:"publicKeyPEM"`
		EncryptedPrivateKeyPEM string `json:"encryptedPrivateKeyPEM"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		fmt.Println("Ошибка декодирования ответа:", err)
		os.Exit(1)
	}
	fmt.Println("Публичный ключ:\n", loginResp.PublicKeyPEM)
	fmt.Println("Зашифрованный приватный ключ:\n", loginResp.EncryptedPrivateKeyPEM)

	// Расшифровка приватного ключа и подпись сообщения
	cryptoMod := crypto.NewECCCrypto()
	privPEM, err := cryptoMod.DecryptPrivateKey(loginResp.EncryptedPrivateKeyPEM, passphrase)
	if err != nil {
		fmt.Println("Ошибка расшифровки приватного ключа:", err)
		os.Exit(1)
	}

	signature, err := cryptoMod.SignMessage(privPEM, []byte(message))
	if err != nil {
		fmt.Println("Ошибка подписи:", err)
		os.Exit(1)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	fmt.Println("Подпись (base64):", signatureB64)

	// Авторизация по подписи
	authzBody := map[string]string{
		"username":  username,
		"message":   message,
		"signature": signatureB64,
	}
	authzData, _ := json.Marshal(authzBody)
	resp, err = http.Post("http://localhost:8080/authz", "application/json", bytes.NewReader(authzData))
	if err != nil {
		fmt.Println("Ошибка запроса /authz:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Ответ /authz:", string(body))
}
