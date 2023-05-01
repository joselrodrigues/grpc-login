package db

import (
	"errors"
	"fmt"
	"login/config"
	"sync"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	dbInstance *gorm.DB
	once       sync.Once
)

func Setup() (*gorm.DB, error) {
	var err error

	once.Do(func() {
		var innerErr error

		cfg, innerErr := config.LoadConfig(".")
		if innerErr != nil {
			err = errors.New("failed to load configuration")
			return
		}
		dsn := buildDSN(cfg)

		dbInstance, innerErr = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if innerErr != nil {
			err = errors.New("failed to connect to the database")
			return
		}
	})

	return dbInstance, err
}

func buildDSN(cfg config.Config) string {
	dsn := "host=%s user=%s password=%s dbname=%s port=%d sslmode=disable"
	return fmt.Sprintf(dsn, cfg.PostgresHost, cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresDB, cfg.PostgresPort)
}
