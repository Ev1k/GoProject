package handlers

import (
	"GoProject/models"
	"html/template"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

var tmpl *template.Template

func InitTemplates(t *template.Template) {
	tmpl = t
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tokenStr := cookie.Value
	claims := &models.Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		secret := os.Getenv("JWT_SECRET")
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	err = tmpl.ExecuteTemplate(w, "home.html", map[string]interface{}{
		"UserID": claims.UserID,
		"Role":   claims.Role,
		"User":   claims,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
