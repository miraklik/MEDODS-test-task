package db

import (
	"fmt"
	"log"
	"test-task/config"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ConnectDB() (*gorm.DB, error) {
	cfg, err := config.Load()
	if err != nil {
		log.Printf("Error loading config: %v", err)
		return nil, fmt.Errorf("error loading config: %v", err)
	}

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Password, cfg.Database.Name)

	db, err := gorm.Open(postgres.Open(connStr), &gorm.Config{})
	if err != nil {
		log.Printf("Error connecting to database: %v", err)
		return nil, fmt.Errorf("error connecting to database: %v", err)
	}

	if err := db.AutoMigrate(&User{}, &RefreshToken{}); err != nil {
		log.Printf("Error migrating database: %v", err)
		return nil, fmt.Errorf("error migrating database: %v", err)
	}

	return db, nil
}
