package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"test-task/config"
	"test-task/db"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type JWTService struct {
	cfg config.Config
}

func NewJWTService(cfg config.Config) *JWTService {
	return &JWTService{cfg: cfg}
}

func (j *JWTService) GenerateToken(user db.User, userIP string) (string, string, error) {
	tokenLifespan, err := strconv.Atoi(j.cfg.JWT.Token_lifespan)
	if err != nil {
		return "", "", fmt.Errorf("invalid TOKEN_HOUR_LIFESPAN: %w", err)
	}

	accessID := uuid.NewString()

	claims := jwt.MapClaims{
		"sub":       user.ID,
		"ip":        userIP,
		"access_id": accessID,
		"exp":       time.Now().Add(time.Hour * time.Duration(tokenLifespan)).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)

	signedToken, err := token.SignedString([]byte(j.cfg.JWT.Secret))
	if err != nil {
		return "", "", err
	}

	return signedToken, accessID, nil
}

func (j *JWTService) GenerateRefreshToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("error generating refresh token: %w", err)
	}

	token := base64.URLEncoding.EncodeToString(b)

	hashed, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return token, string(hashed), nil
}

func CompareRefreshToken(hashed, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
}

func (j *JWTService) ValidateToken(tokenStr string) (*jwt.Token, error) {
	if tokenStr == "" {
		return nil, errors.New("token is missing")
	}

	return jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.cfg.JWT.Secret), nil
	})
}

func GetTokenFromRequest(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	parts := strings.Split(bearerToken, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}

func (j *JWTService) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := GetTokenFromRequest(c)
		token, err := j.ValidateToken(tokenStr)
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token claims"})
			return
		}

		c.Set("user_id", claims["sub"])
		c.Set("access_id", claims["access_id"])
		c.Set("token_ip", claims["ip"])
		c.Next()
	}
}

func CurrentUser(c *gin.Context) (db.User, error) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		return db.User{}, errors.New("user_id not found in context")
	}

	userID, ok := userIDVal.(uint)
	if !ok {
		return db.User{}, errors.New("user_id type assertion failed")
	}

	user, err := db.GetUserById(userID)
	if err != nil {
		return db.User{}, err
	}

	return user, nil
}

func GetClientIP(c *gin.Context) string {
	ip := c.ClientIP()
	if ip == "" {
		ip = c.Request.RemoteAddr
	}
	return ip
}
