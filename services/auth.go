package service

import (
	"context"
	"login/config"
	"login/models"
	pb "login/protos"
	"login/repositories"
	"login/utils"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	pb.UnimplementedAuthServiceServer
}

func (s *Server) SignIn(ctx context.Context, req *pb.Request) (*pb.Response, error) {
	cfg, err := config.LoadConfig(".")
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load configuration.")
	}

	user, err := repositories.GetUserByEmail(req.Email)

	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "Invalid username or password.")
	}

	if err := utils.ComparePassword(req.Password, user.Password); err != nil {
		return nil, status.Error(codes.PermissionDenied, "Invalid username or password.")
	}
	parseAccessTokenKey, _ := utils.ParsePrivateKey(cfg.AccessTokenPrivateKey)
	accessToken, err := utils.CreateToken(cfg.AccessTokenExpiresIn, req.Email, parseAccessTokenKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create access token.")
	}
	parseRefreshAccessTokenKey, _ := utils.ParsePrivateKey(cfg.AccessTokenPrivateKey)
	refreshToken, err := utils.CreateToken(cfg.RefreshTokenExpiresIn, req.Email, parseRefreshAccessTokenKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create refresh token.")
	}

	return &pb.Response{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Server) SignUp(ctx context.Context, req *pb.Request) (*pb.Response, error) {
	cfg, err := config.LoadConfig(".")

	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load configuration.")
	}

	hashedPassword := utils.HashPassword(req.Password)
	user := models.User{Email: req.Email, Password: hashedPassword}

	if _, err := repositories.CreateUser(&user); err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to create user: %v", err)
	}

	parseAccessTokenKey, _ := utils.ParsePrivateKey(cfg.AccessTokenPrivateKey)
	accessToken, err := utils.CreateToken(cfg.AccessTokenExpiresIn, user.Email, parseAccessTokenKey)
	if err != nil {

		return nil, status.Error(codes.Internal, "Failed to create access token.")
	}

	parseRefreshAccessTokenKey, _ := utils.ParsePrivateKey(cfg.RefreshTokenPrivateKey)
	refreshToken, err := utils.CreateToken(cfg.RefreshTokenExpiresIn, user.Email, parseRefreshAccessTokenKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create refresh token.")
	}

	return &pb.Response{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
