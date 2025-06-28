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
		&user.Role, // Добавляем роль
	)
	return user, err
}
