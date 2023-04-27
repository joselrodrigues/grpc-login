package service

import (
	"context"
	pb "login/protos"
	"login/repositories"
	"login/utils"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	pb.UnimplementedAuthServiceServer
}

var exp = time.Now().Add(time.Hour * 72).Unix()

func (s *Server) SignIn(ctx context.Context, req *pb.Request) (*pb.Response, error) {
	jwtSecret := os.Getenv("JWT_SECRET")

	user, err := repositories.FindUserByEmail(req.Email)

	if err != nil {
		return nil, err
	}

	err = utils.CheckPassword(req.Password, user.Password)

	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "Invalid username or password.")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": req.Username,
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
