package models

import "github.com/golang-jwt/jwt/v5"

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

type User struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	TTLockUsername string `json:"ttlock_username"`
	Role           Role   `json:"role"`
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
}

type Claims struct {
	UserID int  `json:"user_id"`
	Role   Role `json:"role"`
	jwt.RegisteredClaims
}
