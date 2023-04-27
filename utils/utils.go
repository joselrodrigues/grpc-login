package utils

import "golang.org/x/crypto/bcrypt"

func CheckPassword(password, hashedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err
}
