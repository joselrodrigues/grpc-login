package service

import (
	"context"
	"login/config"
	"login/models"
	pb "login/protos"
	"login/repositories"
	"login/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

	user, err := repositories.GetUserByEmail(ctx, req.Email)

	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "Invalid username or password.")
	}

	if err := utils.ComparePassword(req.Password, user.Password); err != nil {
		return nil, status.Error(codes.PermissionDenied, "Invalid username or password.")
	}
	parseAccessTokenKey, _ := utils.ParsePrivateKey(cfg.AccessTokenPrivateKey)
	accessToken, err := utils.CreateToken(cfg.AccessTokenExpiresIn, user.ID, parseAccessTokenKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create access token.")
	}
	parseRefreshAccessTokenKey, _ := utils.ParsePrivateKey(cfg.RefreshTokenPrivateKey)
	refreshToken, err := utils.CreateToken(cfg.RefreshTokenExpiresIn, user.ID, parseRefreshAccessTokenKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create refresh token.")
	}

	userData := &utils.User{ID: user.ID, Email: user.Email}
	err = userData.StoreRefreshToken(ctx, cfg.RefreshTokenExpiresIn, refreshToken)

	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to store refresh token.")
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
	accessToken, err := utils.CreateToken(cfg.AccessTokenExpiresIn, user.ID, parseAccessTokenKey)
	if err != nil {

		return nil, status.Error(codes.Internal, "Failed to create access token.")
	}

	parseRefreshAccessTokenKey, _ := utils.ParsePrivateKey(cfg.RefreshTokenPrivateKey)
	refreshToken, err := utils.CreateToken(cfg.RefreshTokenExpiresIn, user.ID, parseRefreshAccessTokenKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create refresh token.")
	}

	userData := &utils.User{ID: user.ID, Email: user.Email}
	err = userData.StoreRefreshToken(ctx, cfg.RefreshTokenExpiresIn, refreshToken)

	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to store refresh token.")
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

func (s *Server) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	cfg, err := config.LoadConfig(".")

	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to load configuration.")
	}

	rawClaims, err := utils.ValidateToken(req.RefreshToken, cfg.RefreshTokenPublicKey)

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid token")
	}

	err = utils.CheckIfRefreshTokenBlocked(ctx, req.RefreshToken)

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Token is blocked")
	}

	claims := rawClaims.(jwt.MapClaims)
	userID := claims["sub"].(string)

	user, err := repositories.GetUserById(ctx, uuid.MustParse(userID))

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid user")
	}

	parseAccessTokenKey, _ := utils.ParsePrivateKey(cfg.AccessTokenPrivateKey)
	accessToken, err := utils.CreateToken(cfg.AccessTokenExpiresIn, user.ID, parseAccessTokenKey)

	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create access token.")
	}

	return &pb.RefreshTokenResponse{
		AccessToken: accessToken,
	}, nil

}
