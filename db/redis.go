package db

import (
	"context"
	"errors"
	"fmt"
	"login/config"
	"sync"

	"github.com/redis/go-redis/v9"
)

var (
	redisClient *redis.Client
	redisOnce   sync.Once
)

func Redis(ctx context.Context) (*redis.Client, error) {
	var err error

	redisOnce.Do(func() {
		var innerErr error

		cfg, innerErr := config.LoadConfig(".")
		if innerErr != nil {
			err = errors.New("failed to load configuration")
			return
		}

		rdb := redis.NewClient(&redis.Options{
			Addr:     cfg.RedisHost,
			Password: cfg.RedisPassword,
			DB:       cfg.RedisDB,
		})

		_, innerErr = rdb.Ping(ctx).Result()
		if innerErr != nil {
			err = fmt.Errorf("failed to connect to Redis: %v", innerErr)
			return
		}

		redisClient = rdb
	})

	return redisClient, err
}
