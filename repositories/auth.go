package repositories

import (
	"context"
	"errors"
	"fmt"
	"login/db"
	"login/models"

	"gorm.io/gorm"
)

func GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	db, _ := db.Setup()

	user := &models.User{}
	result := db.WithContext(ctx).Where("email = ?", email).First(user)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found: %v", result.Error)
		}
		return nil, fmt.Errorf("database error: %v", result.Error)
	}
	return user, nil
}

func CreateUser(user *models.User) (*models.User, error) {
	db, err := db.Setup()

	if err != nil {
		return nil, fmt.Errorf("failed to connect to the database: %w", err)
	}

	if result := db.Create(&user); result.Error != nil {
		return nil, fmt.Errorf("failed to create user: %w", result.Error)
	}

	return user, nil
}
