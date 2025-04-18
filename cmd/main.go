package main

import (
	"log"
	"test-task/config"
	"test-task/db"
	"test-task/handlers"
	"test-task/utils"

	"github.com/gin-gonic/gin"
)

func main() {
	database, err := db.ConnectDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	jwtService := utils.NewJWTService(*cfg)

	r := gin.Default()

	server := handlers.NewServer(database)

	r.POST("/register", server.RegisterUser)
	r.POST("/login", server.LoginUser)

	router2 := r.Group("/auth")
	router2.Use(jwtService.Middleware())
	{
		router2.POST("/token", server.TokenHandler)
		router2.POST("/refresh", server.RefreshHandler)
	}

	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
