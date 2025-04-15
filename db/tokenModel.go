package db

import (
	"time"
)

type RefreshToken struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint
	TokenHash string
	AccessID  string
	IP        string
	CreatedAt time.Time
}
