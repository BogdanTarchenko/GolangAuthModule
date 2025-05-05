package model

type User struct {
	Username       string
	PublicKeyPEM   string
	PassphraseHash []byte
}
