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

//TODO posible impruvement in case that you need to try again to conect without turn down
// all app

// type Database struct {
// 	dbInstance *gorm.DB
// 	mu         sync.Mutex
// 	ready      *sync.Cond
// 	isReady    bool
// }

// func (d *Database) Setup() (*gorm.DB, error) {
// 	d.mu.Lock()
// 	defer d.mu.Unlock()

// 	if d.dbInstance != nil {
// 		return d.dbInstance, nil
// 	}

// 	// If not ready, wait
// 	for !d.isReady {
// 		d.ready.Wait()
// 	}

// 	cfg, err := config.LoadConfig(".")
// 	if err != nil {
// 		return nil, errors.New("failed to load configuration")
// 	}
// 	dsn := buildDSN(cfg)

// 	// Try to connect
// 	dbInstance, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
// 	if err != nil {
// 		return nil, errors.New("failed to connect to the database")
// 	}

// 	// If connected, notify all waiting and return
// 	d.dbInstance = dbInstance
// 	d.isReady = true
// 	d.ready.Broadcast()

// 	return d.dbInstance, nil
// }

// func NewDatabase() *Database {
// 	db := &Database{}
// 	db.ready = sync.NewCond(&db.mu)
// 	return db
// }

// example uses
// dbInstance := NewDatabase()
// user, err := GetUserByEmail(ctx, "email@example.com", dbInstance)

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
