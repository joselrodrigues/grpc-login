package service

import (
	"context"
	pb "login/protos"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Server struct {
	pb.UnimplementedAuthServiceServer
}

var exp = time.Now().Add(time.Hour * 72).Unix()

func (s *Server) SignIn(ctx context.Context, in *pb.Request) (*pb.Response, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": in.Username,
		"exp":      exp,
	})

	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return nil, err
	}

	return &pb.Response{
		AccessToken:  signedToken,
		RefreshToken: "Login successful",
	}, nil
}
