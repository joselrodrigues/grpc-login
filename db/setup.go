package db

import (
	"fmt"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Setup() (*gorm.DB, error) {
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	port := os.Getenv("POSTGRES_PORT")
	dbname := os.Getenv("POSTGRES_DB")
	host := os.Getenv("POSTGRES_HOST")

	dsn := "host=%s user=%s password=%s dbname=%s port=%s sslmode=disable"
	dsn = fmt.Sprintf(dsn, host, user, password, dbname, port)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	return db, err
}
