package db

import (
	"GoProject/models"
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func InitDB() {
	var err error
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)

	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatal(err)
	}

	createTable()
}

func createTable() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
	ttlock_username VARCHAR(200) DEFAULT NULL,
    role VARCHAR(10) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CHECK (role IN ('admin', 'user'))
	);
	`

	_, err := DB.Exec(query)
	if err != nil {
		log.Fatal(err)
	}
}

func CloseDB() {
	DB.Close()
}

func CreateUser(user models.User) error {
	query := `
    INSERT INTO users (name, email, password, role) 
    VALUES ($1, $2, $3, $4)
    RETURNING id`

	var id int
	err := DB.QueryRow(query,
		user.Name,
		user.Email,
		user.Password,
		user.Role, // Добавляем роль
	).Scan(&id)

	if err != nil {
		log.Printf("DB error: %v", err) // Добавьте эту строку
		return err
	}

	return nil
}

func GetUserByEmail(email string) (models.User, error) {
	var user models.User
	query := `SELECT id, name, email, password, role FROM users WHERE email = $1`
	err := DB.QueryRow(query, email).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.Role,
	)
	return user, err
}

func GetTTLockUsername(userID int) (string, error) {
	var username string
	err := DB.QueryRow("SELECT ttlock_username FROM users WHERE id = $1", userID).Scan(&username)
	if err != nil {
		return "", fmt.Errorf("failed to get TTLock username: %w", err)
	}
	return username, nil
}

func GetUserByTTLockUsername(ttlockUsername string) (models.User, error) {
	var user models.User
	query := `SELECT id, name, email, password, role FROM users WHERE ttlock_username = $1`
	err := DB.QueryRow(query, ttlockUsername).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.Role,
	)
	return user, err
}

func SaveTTLockUsername(userID int, ttlockUsername string) error {
	_, err := DB.Exec(
		"UPDATE users SET ttlock_username = $1 WHERE id = $2",
		ttlockUsername,
		userID,
	)
	return err
}
