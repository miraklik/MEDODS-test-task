package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Database struct {
		Host     string `yaml:"host"`
		Port     string `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Name     string `yaml:"name"`
	}

	Server struct {
		Port string `yaml:"port"`
	}

	JWT struct {
		Secret         string `yaml:"secret"`
		Token_lifespan string `yaml:"token_lifespan"`
	}
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		log.Printf("Error loading .env file: %v", err)
		return nil, fmt.Errorf("error loading .env file: %v", err)
	}

	var config Config

	config.Server.Port = os.Getenv("PORT")

	config.Database.Host = os.Getenv("DB_HOST")
	config.Database.Port = os.Getenv("DB_PORT")
	config.Database.User = os.Getenv("DB_USER")
	config.Database.Password = os.Getenv("DB_PASS")
	config.Database.Name = os.Getenv("DB_NAME")

	config.JWT.Secret = os.Getenv("JWT_SECRET")
	config.JWT.Token_lifespan = os.Getenv("JWT_TOKEN_LIFESPAN")

	return &config, nil
}
