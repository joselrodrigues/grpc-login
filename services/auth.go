package service

import (
	"context"
	"fmt"
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
	Cfg config.Config
}

func (s *Server) SignIn(ctx context.Context, req *pb.Request) (*pb.Response, error) {

	user, err := repositories.GetUserByEmail(ctx, req.Email)

	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "invalid username or password")
	}

	if err := utils.ComparePassword(req.Password, user.Password); err != nil {
		return nil, status.Error(codes.PermissionDenied, "invalid username or password")
	}

	token, err := utils.CreateTokens(s.Cfg, user.ID)

	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("%s", err))
	}

	userData := &utils.User{ID: user.ID, Email: user.Email}
	err = userData.StoreRefreshToken(ctx, s.Cfg.RefreshTokenExpiresIn, token.Refresh)

	if err != nil {
		return nil, status.Error(codes.Internal, "failed to store refresh token")
	}

	return &pb.Response{
		AccessToken:  token.Access,
		RefreshToken: token.Refresh,
	}, nil
}

func (s *Server) SignUp(ctx context.Context, req *pb.Request) (*pb.Response, error) {

	hashedPassword := utils.HashPassword(req.Password)
	user := models.User{Email: req.Email, Password: hashedPassword}

	if _, err := repositories.CreateUser(&user); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	token, err := utils.CreateTokens(s.Cfg, user.ID)

	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("%s", err))
	}

	userData := &utils.User{ID: user.ID, Email: user.Email}
	err = userData.StoreRefreshToken(ctx, s.Cfg.RefreshTokenExpiresIn, token.Refresh)

	if err != nil {
		return nil, status.Error(codes.Internal, "failed to store refresh token")
	}

	return &pb.Response{
		AccessToken:  token.Access,
		RefreshToken: token.Refresh,
	}, nil
}

func (s *Server) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {

	rawClaims, err := utils.ValidateToken(req.Token, s.Cfg.AccessTokenPublicKey)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
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

	claims, err := utils.ValidateRefreshToken(ctx, s.Cfg, req.RefreshToken)

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("%s", err))
	}

	userID := claims["sub"].(string)

	user, err := repositories.GetUserById(ctx, uuid.MustParse(userID))

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid user")
	}

	parseAccessTokenKey, _ := utils.ParsePrivateKey(s.Cfg.AccessTokenPrivateKey)
	accessToken, err := utils.CreateToken(s.Cfg.AccessTokenExpiresIn, user.ID, parseAccessTokenKey)

	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create access token")
	}

	return &pb.RefreshTokenResponse{
		AccessToken: accessToken,
	}, nil

}

func (s *Server) SignOut(ctx context.Context, req *pb.DeleteRefreshTokenRequest) (*pb.DeleteRefreshTokenResponse, error) {
	var pattern string

	claims, err := utils.ValidateRefreshToken(ctx, s.Cfg, req.RefreshToken)

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("%s", err))
	}

	userID := claims["sub"].(string)

	user, err := repositories.GetUserById(ctx, uuid.MustParse(userID))

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid user")
	}

	if len(req.SessionId) > 0 {
		pattern = fmt.Sprintf("user:%s:refresh_token:*:session_id:%s", user.ID, req.SessionId)
	} else {
		pattern = fmt.Sprintf("user:%s:refresh_token:%s:session_id:*", user.ID, req.RefreshToken)
	}

	err = utils.DeleteKey(ctx, pattern)

	if err != nil {
		return nil, status.Error(codes.Internal, "failed to sign out")
	}

	return &pb.DeleteRefreshTokenResponse{}, nil
}
