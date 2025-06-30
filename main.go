package main

import (
	"GoProject/db"
	"GoProject/handlers"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func getRecordType(recordType int) string {
	types := map[int]string{
		-5: "Face",
		-4: "QR code",
		4:  "Keyboard password",
		7:  "IC card",
		8:  "Fingerprint",
		55: "Remote",
	}
	if name, ok := types[recordType]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", recordType)
}

// Функция для форматирования Unix времени
func FormatUnix(t int64) string {
	if t == 0 {
		return "N/A"
	}
	return time.Unix(t, 0).Format("2006-01-02 15:04")
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Инициализация базы данных
	db.InitDB()
	defer db.CloseDB()

	tmpl := template.New("").Funcs(template.FuncMap{
		"formatUnix":    FormatUnix,
		"getRecordType": getRecordType,
	})

	_, err = tmpl.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Error parsing templates: %v", err)
	}

	handlers.InitTemplates(tmpl)

	//fs := http.FileServer(http.Dir("static"))
	//http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Настройка маршрутов
	http.HandleFunc("/", handlers.HomeHandler)
	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/locks", handlers.LocksHandler)
	//http.HandleFunc("/ttlock/auth", handlers.TTLockAuthHandler)
	//http.HandleFunc("/ttlock/callback", handlers.TTLockCallbackHandler)
	http.HandleFunc("/api/register", handlers.RegisterAPIHandler)
	http.HandleFunc("/api/login", handlers.LoginAPIHandler)
	http.HandleFunc("/api/ttlock/control", handlers.TTLockControlHandler)
	http.HandleFunc("/records/", handlers.RecordsHandler)
	http.HandleFunc("/ekey", handlers.EKeyHandler)
	http.HandleFunc("/key-period", handlers.KeyPeriodHandler)
	http.HandleFunc("/freeze-key", handlers.FreezeKeyHandler)
	http.HandleFunc("/keys", handlers.KeysHandler)
	http.HandleFunc("/api/ttlock/auth", handlers.TTLockAuthHandler)
	http.HandleFunc("/ttlock/auth", handlers.TTLockAuthGetHandler)
	http.HandleFunc("/initLock", handlers.InitLockHandler)
	http.HandleFunc("/api/ttlock/initialize", handlers.InitLockAPIHandler)

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
	checkTemplate("locks.html")
	checkTemplate("ekey.html")
	checkTemplate("key_period.html")
	checkTemplate("freeze_key.html")
	checkTemplate("keys.html")
	checkTemplate("records.html")
	checkTemplate("ttlock_auth.html")
	checkTemplate("init_lock.html")
	tmpl.Funcs(template.FuncMap{
		"formatUnix": FormatUnix,
	})
	// Запуск сервера
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on port %s...", port)
	fmt.Println(time.Now().UnixMilli())
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
