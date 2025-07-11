package handlers

import (
	"GoProject/db"
	"GoProject/models"
	_ "GoProject/models"
	"GoProject/ttlock"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ttClient   *ttlock.TTLockClient
	clientOnce sync.Once
)

func InitTTLockClient() {
	clientOnce.Do(func() {
		ttClient = &ttlock.TTLockClient{}
	})
}

func InitLockHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("token"); err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	tmpl.ExecuteTemplate(w, "init_lock.html", nil)
}

func InitLockAPIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cookie, err := r.Cookie("token")
	if err != nil {
		respondWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"message": "Authentication required",
		})
		return
	}

	claims := &models.Claims{}
	_, err = jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		respondWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"message": "Invalid token",
		})
		return
	}
	user, err := db.GetUserByID(claims.UserID)
	accessToken := user.AccessToken
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Failed to get access token",
		})
		return
	}

	var reqData struct {
		LockData  string `json:"lockData"`
		LockAlias string `json:"lockAlias"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": "Invalid request data",
		})
		return
	}

	ttClient := ttlock.NewClient()
	lockInit, err := ttClient.InitializeLock(accessToken, reqData.LockData, reqData.LockAlias)
	if err != nil {
		log.Printf("Failed to initialize lock: %v", err)
		respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Lock initialized successfully",
		"lockId":  lockInit.LockId,
		"keyId":   lockInit.KeyId,
	})
}

func LocksHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	InitTTLockClient()
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		secret := os.Getenv("JWT_SECRET")
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		fmt.Println(err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	locks, err := ttClient.ListLocks(1, 20, 0, "", claims.UserID) // без фильтров
	if err != nil {
		log.Printf("Failed to get locks: %v", err)
		http.Error(w, "Failed to get locks", http.StatusInternalServerError)
		return
	}

	for i := range locks.List {
		config, err := ttClient.GetPassageMode(locks.List[i].ID)
		if err != nil {
			log.Printf("Failed to get passage mode for lock %d: %v", locks.List[i].ID, err)
			locks.List[i].Status = "Неизвестно"
			continue
		}

		if config.PassageMode == 1 {
			locks.List[i].Status = "Открыт"
		} else {
			locks.List[i].Status = "Закрыт"
		}
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") || r.URL.Query().Get("format") == "json" {
		// REST API response
		respondWithJSON(w, http.StatusOK, locks)
	} else {
		// HTML response (для обратной совместимости)
		err = tmpl.ExecuteTemplate(w, "locks.html", map[string]interface{}{
			"Locks": locks.List,
		})
		if err != nil {
			log.Printf("Failed to render locks page: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Internal server error")
		}
	}
}

func TTLockControlHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LockID int    `json:"lockId"`
		Action string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ttClient := ttlock.NewClient()

	passageMode := 1
	if req.Action == "2" {
		passageMode = 2
	}

	err := ttClient.ConfigurePassageMode(req.LockID, passageMode, 2)
	if err != nil {
		log.Printf("Failed to control lock: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func RecordsHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		secret := os.Getenv("JWT_SECRET")
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	lockIDStr := strings.TrimPrefix(r.URL.Path, "/records/")
	lockID, err := strconv.Atoi(lockIDStr)
	if err != nil {
		http.Error(w, "Invalid lock ID", http.StatusBadRequest)
		return
	}

	startDate := r.URL.Query().Get("startDate")
	endDate := r.URL.Query().Get("endDate")

	var startTimestamp, endTimestamp int64
	if startDate != "" {
		t, err := time.Parse("2006-01-02", startDate)
		if err == nil {
			startTimestamp = t.Unix() * 1000
		}
	}
	if endDate != "" {
		t, err := time.Parse("2006-01-02", endDate)
		if err == nil {
			endTimestamp = t.Unix() * 1000
		}
	}

	ttClient := ttlock.NewClient()
	records, err := ttClient.GetLockRecords(lockID, startTimestamp, endTimestamp)
	if err != nil {
		log.Printf("Failed to get lock records: %v", err)
		http.Error(w, "Failed to get lock records", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"lockId":   lockID,
		"list":     records.List,
		"pageNo":   records.PageNo,
		"pageSize": records.PageSize,
		"pages":    records.Pages,
		"total":    records.Total,
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") || r.URL.Query().Get("format") == "json" {
		respondWithJSON(w, http.StatusOK, response)
	} else {
		err = tmpl.ExecuteTemplate(w, "records.html", response)
		if err != nil {
			log.Printf("Failed to render records page: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Internal server error")
		}
	}
}

func EKeyHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		secret := os.Getenv("JWT_SECRET")
		return []byte(secret), nil
	})

	if err != nil || !token.Valid || claims.Role != "admin" {
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "ekey.html", nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	lockID, _ := strconv.Atoi(r.FormValue("lockId"))
	receiverUsername := r.FormValue("receiverUsername")
	keyName := r.FormValue("keyName")
	remarks := r.FormValue("remarks")

	startDate, err1 := time.Parse("2006-01-02", r.FormValue("startDate"))
	endDate, err2 := time.Parse("2006-01-02", r.FormValue("endDate"))

	if err1 != nil || err2 != nil {
		http.Error(w, "Invalid date format", http.StatusBadRequest)
		return
	}

	ttClient := ttlock.NewClient()
	keyID, err := ttClient.SendEKey(lockID, receiverUsername, keyName, startDate, endDate, remarks)

	if err != nil {
		tmpl.ExecuteTemplate(w, "ekey.html", map[string]interface{}{
			"Error": fmt.Sprintf("Failed to send eKey: %v", err),
		})
		return
	}

	tmpl.ExecuteTemplate(w, "ekey.html", map[string]interface{}{
		"Success": fmt.Sprintf("EKey successfully sent! Key ID: %d", keyID),
	})
}

func KeyPeriodHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		secret := os.Getenv("JWT_SECRET")
		return []byte(secret), nil
	})

	if err != nil || !token.Valid || claims.Role != "admin" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "key_period.html", nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	keyID, _ := strconv.Atoi(r.FormValue("keyId"))

	startDate, err1 := time.Parse("2006-01-02", r.FormValue("startDate"))
	endDate, err2 := time.Parse("2006-01-02", r.FormValue("endDate"))

	if err1 != nil || err2 != nil {
		tmpl.ExecuteTemplate(w, "key_period.html", map[string]interface{}{
			"Error": "Invalid date format",
		})
		return
	}

	ttClient := ttlock.NewClient()
	err = ttClient.ChangeKeyPeriod(keyID, startDate, endDate)

	if err != nil {
		tmpl.ExecuteTemplate(w, "key_period.html", map[string]interface{}{
			"Error": fmt.Sprintf("Failed to change key period: %v", err),
		})
		return
	}

	tmpl.ExecuteTemplate(w, "key_period.html", map[string]interface{}{
		"Success": "Key access period successfully updated!",
	})
}

func FreezeKeyHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		secret := os.Getenv("JWT_SECRET")
		return []byte(secret), nil
	})

	if err != nil || !token.Valid || claims.Role != "admin" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "freeze_key.html", nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	keyID, err := strconv.Atoi(r.FormValue("keyId"))
	if err != nil {
		tmpl.ExecuteTemplate(w, "freeze_key.html", map[string]interface{}{
			"Error": "Invalid Key ID format",
		})
		return
	}

	ttClient := ttlock.NewClient()
	err = ttClient.FreezeKey(keyID)

	if err != nil {
		tmpl.ExecuteTemplate(w, "freeze_key.html", map[string]interface{}{
			"Error": fmt.Sprintf("Failed to freeze key: %v", err),
		})
		return
	}

	tmpl.ExecuteTemplate(w, "freeze_key.html", map[string]interface{}{
		"Success": fmt.Sprintf("Key %d successfully frozen!", keyID),
	})
}

func KeysHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		secret := os.Getenv("JWT_SECRET")
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		lockID, err := strconv.Atoi(r.FormValue("lockId"))
		if err != nil {
			tmpl.ExecuteTemplate(w, "keys.html", map[string]interface{}{
				"Error": "Invalid Lock ID format",
			})
			return
		}

		ttClient := ttlock.NewClient()
		keysResp, err := ttClient.ListKeys(lockID, 1, 200, 0, "") // pageNo=1, pageSize=200, orderBy=0

		if err != nil {
			tmpl.ExecuteTemplate(w, "keys.html", map[string]interface{}{
				"Error":  fmt.Sprintf("Failed to get keys: %v", err),
				"LockID": lockID,
			})
			return
		}

		//for i := range keysResp.List {
		//	keysResp.List[i].StartDate = keysResp.List[i].StartDate / 1000
		//	keysResp.List[i].EndDate = keysResp.List[i].EndDate / 1000
		//	keysResp.List[i].Date = keysResp.List[i].Date / 1000
		//}

		for i := range keysResp.List {
			if keysResp.List[i].StartDate > 0 {
				keysResp.List[i].StartDate = keysResp.List[i].StartDate / 1000
			}
			if keysResp.List[i].EndDate > 0 {
				keysResp.List[i].EndDate = keysResp.List[i].EndDate / 1000
			}
			if keysResp.List[i].Date > 0 {
				keysResp.List[i].Date = keysResp.List[i].Date / 1000
			}
		}

		tmpl.ExecuteTemplate(w, "keys.html", map[string]interface{}{
			"LockID": lockID,
			"Keys":   keysResp.List,
		})
		return
	}

	tmpl.ExecuteTemplate(w, "keys.html", nil)
}
