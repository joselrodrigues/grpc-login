package repositories

import (
	"errors"
	"fmt"
	"login/db"
	"login/models"

	"gorm.io/gorm"
)

func FindUserByEmail(email string) (*models.User, error) {
	db, _ := db.Setup()

	user := models.User{Email: email}
	result := db.First(&user)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found: %v", result.Error)
		}
		return nil, fmt.Errorf("database error: %v", result.Error)
	}
	return &user, nil
}
