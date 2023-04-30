package service

import (
	"context"
	"login/config"
	"login/models"
	pb "login/protos"
	"login/repositories"
	"login/utils"

	"github.com/golang-jwt/jwt/v5"
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

func (s *Server) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	cfg, err := config.LoadConfig(".")

	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load configuration.")
	}
	rawClaims, err := utils.ValidateToken(req.Token, cfg.AccessTokenPublicKey)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid token")
	}

	claims := rawClaims.(jwt.MapClaims)

	pbClaims := &pb.JWTClaims{
		Sub: claims["sub"].(string),
		Exp: int64(claims["exp"].(float64)),
		Iat: int64(claims["iat"].(float64)),
		Nbf: int64(claims["nbf"].(float64)),
	}

	return &pb.ValidateTokenResponse{
		Claims: pbClaims,
	}, nil
}
