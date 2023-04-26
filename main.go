package main

import (
	"log"
	"login/db"
	logger "login/log"
	pb "login/protos"
	service "login/services"
	"net"

	"github.com/joho/godotenv"
	"google.golang.org/grpc"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	logger.Setup()
	db.Configuration()

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()

	pb.RegisterAuthServiceServer(s, &service.Server{})
	log.Println("gRPC server listening on port 50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
