package handlers

import (
	"log"
	"net/http"
	"test-task/config"
	"test-task/db"
	"test-task/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type RegisterUser struct {
	Email           string `json:"email"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	PasswordConfirm string `json:"passwordConfirm"`
}

type LoginUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RefreshInput struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Server struct {
	db *gorm.DB
}

func NewServer(db *gorm.DB) *Server {
	return &Server{db: db}
}

func (s *Server) RegisterUser(c *gin.Context) {
	var Input RegisterUser

	if err := c.ShouldBindJSON(&Input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := db.User{
		Email:    Input.Email,
		Nickname: Input.Username,
		Password: Input.Password,
	}
	if err := utils.ValidatePassword(Input.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := user.HashedPassword(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to hash password: " + err.Error()})
		return
	}

	if user.Email == "" || user.Nickname == "" || user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
		return
	}

	if Input.Password != Input.PasswordConfirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "passwords do not match"})
		return
	}

	if err := s.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user created successfully"})
}

func (s *Server) LoginUser(c *gin.Context) {
	var Input LoginUser

	if err := c.ShouldBindJSON(&Input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := db.User{Nickname: Input.Username, Password: Input.Password}

	token, err := s.LoginCheck(user.Nickname, user.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (s *Server) LoginCheck(username, password string) (string, error) {
	var err error
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	util := utils.NewJWTService(*cfg)

	user := db.User{}

	if err = s.db.Model(db.User{}).Where("username=?", username).Take(&user).Error; err != nil {
		return "", err
	}

	err = db.VerifyPassword(password, user.Password)

	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		return "", err
	}

	var c *gin.Context

	token, _, err := util.GenerateToken(user, utils.GetClientIP(c))

	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *Server) TokenHandler(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	var user db.User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	cfg, _ := config.Load()
	jwtSvc := utils.NewJWTService(*cfg)
	ip := utils.GetClientIP(c)

	accessToken, accessID, err := jwtSvc.GenerateToken(user, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		return
	}

	refreshToken, refreshHash, err := jwtSvc.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	rt := db.RefreshToken{
		UserID:    user.ID,
		TokenHash: refreshHash,
		AccessID:  accessID,
		IP:        ip,
	}
	if err := s.db.Create(&rt).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (s *Server) RefreshHandler(c *gin.Context) {
	var input RefreshInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	cfg, _ := config.Load()
	jwtSvc := utils.NewJWTService(*cfg)
	token, err := jwtSvc.ValidateToken(input.AccessToken)
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access token"})
		return
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	userID := claims["sub"].(string)
	accessID := claims["access_id"].(string)
	originalIP := claims["ip"].(string)
	newIP := utils.GetClientIP(c)

	var user db.User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	var stored db.RefreshToken
	if err := s.db.Where("user_id = ? AND access_id = ?", userID, accessID).First(&stored).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token not found"})
		return
	}

	if err := utils.CompareRefreshToken(stored.TokenHash, input.RefreshToken); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if originalIP != newIP {
		log.Printf("IP change detected for user %s: %s -> %s", user.Email, originalIP, newIP)
	}

	accessToken, newAccessID, err := jwtSvc.GenerateToken(user, newIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate new access token"})
		return
	}

	refreshToken, refreshHash, err := jwtSvc.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate new refresh token"})
		return
	}

	s.db.Delete(&stored)
	s.db.Create(&db.RefreshToken{
		UserID:    user.ID,
		TokenHash: refreshHash,
		AccessID:  newAccessID,
		IP:        newIP,
	})

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}
