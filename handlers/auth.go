package handlers

import (
	"GoProject/db"
	"GoProject/models"
	"GoProject/ttlock"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultTokenExpiration = 24 * time.Hour
	tokenCookieName        = "token"
)

var (
	jwtSecret     []byte
	jwtSecretOnce sync.Once
)

type RegistrationRequest struct {
	Name            string      `json:"name"`
	Email           string      `json:"email"`
	Password        string      `json:"password"`
	PasswordConfirm string      `json:"password_confirm"`
	Role            models.Role `json:"role"`
}

func initJWTSecret() {
	jwtSecretOnce.Do(func() {
		secret := os.Getenv("JWT_SECRET")
		if secret != "" {
			jwtSecret = []byte(secret)
			return
		}

		newSecret := make([]byte, 64)
		if _, err := rand.Read(newSecret); err != nil {
			panic("failed to generate JWT secret: " + err.Error())
		}
		jwtSecret = []byte(base64.StdEncoding.EncodeToString(newSecret))
	})
}

func generateToken(user *models.User) (string, error) {
	initJWTSecret()

	claims := models.Claims{
		UserID: user.ID,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(defaultTokenExpiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "GoProject",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(jwtSecret)
}

func setTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     tokenCookieName,
		Value:    token,
		Expires:  time.Now().Add(defaultTokenExpiration),
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})
}

func validateRegistration(req RegistrationRequest) error {
	log.Printf("Validating: %+v", req) // Добавьте логирование
	if req.Name == "" {
		return errors.New("name is required")
	}
	if req.Email == "" {
		return errors.New("email is required")
	}
	if len(req.Password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if req.Password != req.PasswordConfirm {
		return errors.New("passwords do not match")
	}
	if req.Role != "" && req.Role != models.RoleUser && req.Role != models.RoleAdmin {
		return errors.New("invalid role")
	}
	return nil
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "register.html", nil)
		return
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}
}

func RegisterAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := validateRegistration(req); err != nil {
		log.Printf("Registration error: %v", err)
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}
	if req.Role == "" {
		req.Role = models.RoleUser
	}

	user := models.User{
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hashedPassword),
		Role:     req.Role,
	}

	userId, err := db.CreateUser(user)
	if err != nil {
		if err.Error() == "pq: duplicate key value violates unique constraint" {
			respondWithError(w, http.StatusBadRequest, "Email already exists")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	ttlockClient := ttlock.NewClient()
	ttUsername := strings.ToLower(strings.ReplaceAll(req.Email, "@", ""))
	ttUsername = regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(ttUsername, "")
	ttPassword := req.Password

	log.Printf("Registering in TTLock with username: %s", ttUsername)
	registeredUsername, err := ttlockClient.RegisterUser(ttUsername, ttPassword)
	if err != nil {
		log.Printf("TTLock registration failed: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to register in TTLock service")
		return
	}

	log.Printf("Successfully registered in TTLock with username: %s", registeredUsername)
	if err := db.SaveTTLockUsername(userId, registeredUsername); err != nil {
		log.Printf("Failed to save TTLock username: %v", err)
		respondWithError(w, http.StatusInternalServerError, "User created but failed to save TTLock username")
		return
	}
	fmt.Println(userId, registeredUsername, user.TTLockUsername)
	respondWithJSON(w, http.StatusCreated, map[string]string{
		"message":         "User registered successfully",
		"role":            string(user.Role),
		"ttlock_username": registeredUsername,
	})
}

func LoginAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	user, err := db.GetUserByEmail(creds.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	tokenString, err := generateToken(&user)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	setTokenCookie(w, tokenString)

	ttlockUsername, err := db.GetTTLockUsername(user.ID)
	if err != nil {
		log.Printf("Failed to get TTLock username: %v", err)
		respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success":  false,
			"redirect": "/",
		})
		return
	}

	ttClient := ttlock.NewClient()

	tokens, err := ttClient.Authenticate(ttlockUsername, creds.Password)
	//if err != nil {
	//	log.Printf("TTLock authentication failed: %v", err)
	//} else {
	//	log.Printf("Successfully authenticated with TTLock")
	//}

	err = db.SaveAccessToken(user.ID, tokens.AccessToken)
	if err != nil {
		log.Printf("Failed to save TTLock access token: %v", err)
	}
	err = db.SaveRefreshToken(user.ID, tokens.RefreshToken)
	if err != nil {
		log.Printf("Failed to save TTLock refresh token: %v", err)
	}

	log.Printf("Successfully authenticated with TTLock for user %d", user.ID)

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"redirect": "/",
		"user": map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}
