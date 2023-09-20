
# About The Project

This project is developed using the Go programming language (often referred to as Golang) and utilizes the gRPC protocol. My main objective is to implement a login system leveraging JWT (JSON Web Tokens) for authentication and managing user sessions.

## Getting Started

Clone the project

```bash
  git clone https://github.com/joselrodrigues/grpc-login.git
```

Go to the project directory

```bash
  cd grpc-login
```

Create redis db

```bash
docker run --name redis -d -p 6379:6379 redis redis-server --requirepass "SUPER_SECRET_PASSWORD"
```

Create postgres db

```bash
docker run --name postgres-db -e POSTGRES_PASSWORD=docker -p 5432:5432 -d postgres
```

Install dependencies

```bash
  go mod download
```

Start the server

```bash
  go run main.go
```


## Environment Variables

To run this project, you will need to add the following environment variables to your .env file

```
 ACCESS_TOKEN_PRIVATE_KEY={base64 PEM}
 ACCESS_TOKEN_PUBLIC_KEY={base64 PEM}
 REFRESH_TOKEN_PRIVATE_KEY={base64 PEM}
 REFRESH_TOKEN_PUBLIC_KEY={base64 PEM}
 ACCESS_TOKEN_EXPIRED_IN=15m
 ACCESS_TOKEN_MAXAGE=15
 REFRESH_TOKEN_EXPIRED_IN=60m
 REFRESH_TOKEN_MAXAGE=60
 POSTGRES_USER=postgres
 POSTGRES_PASSWORD=docker
 POSTGRES_PORT=5432
 POSTGRES_DB=postgres
 POSTGRES_HOST=localhost
 REDIS_HOST=localhost:6379
 REDIS_PASSWORD=SUPER_SECRET_PASSWORD
 REDIS_DB=0
 MAX_NUM_SESSIONS=5
 ```

## Usefull commands 

Add submodule
```
git submodule add git@github.com:joselrodrigues/shared-proto.git ./protos

```
Create private PEM file

```
openssl genpkey -algorithm RSA -out refresh_token_private.pem -pkeyopt rsa_keygen_bits:2048
```

Create public PEM file

```
openssl rsa -pubout -in refresh_private_key.pem -out refresh_public_key.pem
```
