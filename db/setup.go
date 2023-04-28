package db

import (
	"fmt"
	"login/config"
	"sync"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	dbInstance *gorm.DB
	once       sync.Once
	setupErr   error
)

func Setup() (*gorm.DB, error) {
	once.Do(func() {
		cfg, err := config.LoadConfig(".")

		if err != nil {
			setupErr = err
			return
		}

		dsn := buildDSN(cfg)

		dbInstance, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			dbInstance = nil
			setupErr = err
			return
		}
	})

	if setupErr != nil {
		return nil, setupErr
	}

	if dbInstance == nil {
		return nil, fmt.Errorf("failed to connect to the database")
	}

	return dbInstance, nil
}

func buildDSN(cfg config.Config) string {
	dsn := "host=%s user=%s password=%s dbname=%s port=%d sslmode=disable"
	return fmt.Sprintf(dsn, cfg.PostgresHost, cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresDB, cfg.PostgresPort)
}
