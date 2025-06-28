package main

import (
	"GoProject/db"
	"GoProject/handlers"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	// Загрузка переменных окружения
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Инициализация базы данных
	db.InitDB()
	defer db.CloseDB()

	//fs := http.FileServer(http.Dir("static"))
	//http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Настройка маршрутов
	http.HandleFunc("/", handlers.HomeHandler)
	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/api/register", handlers.RegisterAPIHandler)
	http.HandleFunc("/api/login", handlers.LoginAPIHandler)

	// Проверка шаблонов
	_, err = os.Stat("templates")
	if os.IsNotExist(err) {
		log.Fatal("Templates directory not found")
	}

	// Проверка отдельных шаблонов
	checkTemplate := func(name string) {
		_, err := os.Stat(filepath.Join("templates", name))
		if err != nil {
			log.Printf("Template %s not found: %v", name, err)
		}
	}

	checkTemplate("base.html")
	checkTemplate("home.html")
	checkTemplate("login.html")
	checkTemplate("register.html")

	// Запуск сервера
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
