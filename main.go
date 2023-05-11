package main

import (
	"log"
	"login/db"
	logger "login/log"
	pb "login/protos"
	service "login/services"
	"net"

	"google.golang.org/grpc"
)

func main() {
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
