package utils

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"login/config"
	"login/db"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/metadata"
)

type User struct {
	ID    uuid.UUID
	Email string
}

type Token struct {
	Access  string
	Refresh string
}

type SessionData struct {
	RefreshToken   string    `json:"refresh_token"`
	SessionID      uuid.UUID `json:"session_id"`
	UserID         string    `json:"user_id"`
	LoginTimestamp int64     `json:"login_timestamp"`
	UserAgent      string    `json:"user_agent"`
}

type filterSession struct {
	SessionID      uuid.UUID `json:"session_id"`
	LoginTimestamp int64     `json:"login_timestamp"`
	UserAgent      string    `json:"user_agent"`
}

func ComparePassword(password, hashedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err
}

func HashPassword(password string) string {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashedPassword)
}

func ParsePrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return key, nil
}

func ParsePublicKey(publicKey string) (*rsa.PublicKey, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return key, nil
}

func CreateToken(ttl time.Duration, payload interface{}, privateKey *rsa.PrivateKey) (string, error) {

	now := time.Now().UTC()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": payload,
		"exp": now.Add(ttl).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	})

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signedToken, nil
}

func ValidateToken(token string, publicKey string) (interface{}, error) {

	key, err := ParsePublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (u *User) StoreRefreshToken(ctx context.Context, ttl time.Duration, refreshToken string) error {
	sessionID := uuid.New()
	refreshTokenKey := fmt.Sprintf("user:%s:refresh_token:%s:session_id:%s", u.ID.String(), refreshToken, sessionID)

	rdb, err := db.Redis(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return fmt.Errorf("failed to retrieve metadata from context")
	}

	userAgent, ok := md["user-device"]

	if !ok {
		return fmt.Errorf("failed to retrieve user-agent from metadata")
	}

	if len(userAgent) == 0 {
		return fmt.Errorf("invalid user-agent")
	}

	now := time.Now().UTC()

	dataSession := &SessionData{UserID: u.ID.String(), RefreshToken: refreshToken, SessionID: sessionID, UserAgent: userAgent[0], LoginTimestamp: now.Unix()}

	dataSessionJson, err := json.Marshal(dataSession)

	if err != nil {
		return fmt.Errorf("failed to store session data")
	}

	pipe := rdb.TxPipeline()

	pipe.Set(ctx, refreshTokenKey, dataSessionJson, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	return nil
}

func CheckIfRefreshTokenBlocked(ctx context.Context, refreshToken string) error {
	query := fmt.Sprintf("user:*:refresh_token:%s:session_id:*", refreshToken)

	rdb, err := db.Redis(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}
	//TODO change KEYS is not performant
	keys, err := rdb.Keys(ctx, query).Result()
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		return fmt.Errorf("refresh token is blocked")
	}

	return nil
}

func CreateTokens(cfg config.Config, userID uuid.UUID) (*Token, error) {

	parseAccessTokenKey, err := ParsePrivateKey(cfg.AccessTokenPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token")
	}
	accessToken, err := CreateToken(cfg.AccessTokenExpiresIn, userID, parseAccessTokenKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token")
	}

	parseRefreshAccessTokenKey, err := ParsePrivateKey(cfg.RefreshTokenPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token")
	}
	refreshToken, err := CreateToken(cfg.RefreshTokenExpiresIn, userID, parseRefreshAccessTokenKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token")
	}

	return &Token{Access: accessToken, Refresh: refreshToken}, nil
}

func DeleteKey(ctx context.Context, pattern string) error {
	rdb, err := db.Redis(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}
	//TODO change KEYS is not performant
	keys, err := rdb.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to retrieve keys: %w", err)
	}

	if len(keys) == 0 {
		return fmt.Errorf("no keys found for token")
	}

	result, err := rdb.Del(ctx, keys...).Result()
	if err != nil {
		return fmt.Errorf("failed to delete keys: %w", err)
	}

	if result == 0 {
		return fmt.Errorf("no keys were deleted")
	}

	return nil
}

func ValidateRefreshToken(ctx context.Context, cfg config.Config, refreshToken string) (jwt.MapClaims, error) {

	rawClaims, err := ValidateToken(refreshToken, cfg.RefreshTokenPublicKey)

	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	err = CheckIfRefreshTokenBlocked(ctx, refreshToken)

	if err != nil {
		return nil, fmt.Errorf("token is blocked")
	}

	return rawClaims.(jwt.MapClaims), nil
}

func GetSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rdb, err := db.Redis(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	var keys []string
	var cursor uint64
	pattern := fmt.Sprintf("user:%s:refresh_token:*:session_id:*", userID)

	for {
		var batch []string
		batch, cursor, err = rdb.Scan(ctx, cursor, pattern, 10).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to scan keys: %w", err)
		}
		keys = append(keys, batch...)
		if cursor == 0 {
			break
		}
	}

	return keys, nil
}

func GetSessionDataByUserID(ctx context.Context, userID uuid.UUID, refreshToken string) ([]filterSession, error) {
	rdb, err := db.Redis(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	keys, err := GetSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	var session SessionData
	var sessions []filterSession

	for _, key := range keys {
		sessionData, err := rdb.Get(ctx, key).Result()
		if err != nil {
			return nil, fmt.Errorf("error getting session data from Redis")
		}

		err = json.Unmarshal([]byte(sessionData), &session)

		if err != nil {
			return nil, fmt.Errorf("error deserializing session data")
		}
		if refreshToken != session.RefreshToken {
			sessions = append(sessions, filterSession{
				SessionID:      session.SessionID,
				LoginTimestamp: session.LoginTimestamp,
				UserAgent:      session.UserAgent,
			})
		}

	}
	return sessions, nil
}
