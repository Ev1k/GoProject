package ttlock

import (
	"GoProject/db"
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	baseURL = "https://euapi.ttlock.com/v3"
)

var (
	clientID     string
	clientSecret string
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found")
	}
	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	fmt.Println(clientID, clientSecret)
	//fmt.Printf(clientID, clientSecret)
	//if clientID == "" || clientSecret == "" {
	//	panic("CLIENT_ID and CLIENT_SECRET must be set in environment variables")
	//}
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	UID          int    `json:"uid"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type TTLockClient struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	UID          int
}

type LockRecordsResponse struct {
	List     []LockRecord `json:"list"`
	PageNo   int          `json:"pageNo"`
	PageSize int          `json:"pageSize"`
	Pages    int          `json:"pages"`
	Total    int          `json:"total"`
}

type LockRecord struct {
	RecordID           int64  `json:"recordId"`
	LockID             int    `json:"lockId"`
	RecordTypeFromLock int    `json:"recordTypeFromLock"`
	RecordType         int    `json:"recordType"`
	Success            int    `json:"success"`
	Username           string `json:"username"`
	KeyboardPwd        string `json:"keyboardPwd"`
	LockDate           int64  `json:"lockDate"`
	ServerDate         int64  `json:"serverDate"`
}

type Lock struct {
	ID           int    `json:"lockId"`
	Name         string `json:"lockName"`
	Alias        string `json:"lockAlias"`
	Mac          string `json:"lockMac"`
	Battery      int    `json:"electricQuantity"`
	FeatureValue string `json:"featureValue"`
	HasGateway   int    `json:"hasGateway"`
	LockData     string `json:"lockData"`
	GroupID      int    `json:"groupId"`
	GroupName    string `json:"groupName"`
	InitDate     int64  `json:"date"`
	Status       string `json:"-"` // Поле для статуса, не приходит из API
}

type LocksResponse struct {
	List     []Lock `json:"list"`
	PageNo   int    `json:"pageNo"`
	PageSize int    `json:"pageSize"`
	Pages    int    `json:"pages"`
	Total    int    `json:"total"`
}

type Key struct {
	KeyID          int    `json:"keyId"`
	LockID         int    `json:"lockId"`
	Username       string `json:"username"`
	UserID         int    `json:"uid"`
	KeyName        string `json:"keyName"`
	KeyStatus      string `json:"keyStatus"`
	StartDate      int64  `json:"startDate"`
	EndDate        int64  `json:"endDate"`
	KeyRight       int    `json:"keyRight"`
	RemoteEnable   int    `json:"remoteEnable"`
	SenderUsername string `json:"senderUsername"`
	Remarks        string `json:"remarks"`
	Date           int64  `json:"date"`
}

type KeysResponse struct {
	List     []Key `json:"list"`
	PageNo   int   `json:"pageNo"`
	PageSize int   `json:"pageSize"`
	Pages    int   `json:"pages"`
	Total    int   `json:"total"`
}

type PassageModeConfig struct {
	PassageMode  int            `json:"passageMode"`
	CyclicConfig []CyclicConfig `json:"cyclicConfig"`
	AutoUnlock   int            `json:"autoUnlock"`
}

type CyclicConfig struct {
	IsAllDay  int   `json:"isAllDay"`
	StartTime int   `json:"startTime,omitempty"`
	EndTime   int   `json:"endTime,omitempty"`
	WeekDays  []int `json:"weekDays,omitempty"`
}

func NewClient() *TTLockClient {
	return &TTLockClient{}
}

func (c *TTLockClient) RegisterUser(username, password string) (string, error) {
	hashedPassword := fmt.Sprintf("%x", md5.Sum([]byte(password)))
	log.Printf("Registering user with username: %s, hashed password: %s", username, hashedPassword)

	//data := url.Values{}
	//data.Set("clientId", clientID)
	//data.Set("clientSecret", clientSecret)
	//data.Set("username", username)
	//data.Set("password", hashedPassword)
	//data.Set("date", fmt.Sprintf("%d", time.Now().UnixMilli()))
	//// Создаем буфер для тела запроса
	//body := strings.NewReader(data.Encode())

	payload := fmt.Sprintf(
		"clientId=%s&clientSecret=%s&username=%s&password=%s&date=%d",
		clientID,
		clientSecret,
		username,
		hashedPassword,
		time.Now().UnixMilli(),
	)
	//log.Printf("Escaped ClientID: %s", url.QueryEscape(clientID))
	//log.Printf("Escaped ClientSecret: %s", url.QueryEscape(clientSecret))
	log.Printf("Request payload: %s", payload)

	// Создаем запрос
	req, err := http.NewRequest(
		"POST",
		baseURL+"/user/register",
		strings.NewReader(payload),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("Response Status: %d", resp.StatusCode)
	log.Printf("Response Body: %s", string(responseBody))

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			ErrCode int    `json:"errcode"`
			ErrMsg  string `json:"errmsg"`
		}
		if err := json.Unmarshal(responseBody, &errorResp); err != nil {
			return "", fmt.Errorf("failed to decode error response: %w", err)
		}
		return "", fmt.Errorf("TTLock API error %d: %s", errorResp.ErrCode, errorResp.ErrMsg)
	}

	var result struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		username := strings.TrimSpace(string(responseBody))
		if username == "" {
			return "", fmt.Errorf("empty username in response")
		}
		return username, nil
	}

	if result.Username == "" {
		return "", fmt.Errorf("empty username in JSON response")
	}

	return result.Username, nil
}

func (c *TTLockClient) Authenticate(username, password string) (*TokenResponse, error) {
	hashedPassword := fmt.Sprintf("%x", md5.Sum([]byte(password)))
	log.Printf("Authenticating user: %s", username)

	payload := fmt.Sprintf(
		"clientId=%s&clientSecret=%s&username=%s&password=%s",
		clientID,
		clientSecret,
		username,
		hashedPassword,
	)

	req, err := http.NewRequest(
		"POST",
		"https://euapi.ttlock.com/oauth2/token",
		strings.NewReader(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("Auth response status: %d, body: %s", resp.StatusCode, string(body))

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil, fmt.Errorf("unexpected content type: %s, body: %s", contentType, string(body))
	}

	if resp.StatusCode != http.StatusOK {
		var apiError struct {
			ErrCode int    `json:"errcode"`
			ErrMsg  string `json:"errmsg"`
		}
		if err := json.Unmarshal(body, &apiError); err != nil {
			return nil, fmt.Errorf("failed to parse error response (status %d): %w, body: %s",
				resp.StatusCode, err, string(body))
		}
		return nil, fmt.Errorf("API error %d: %s", apiError.ErrCode, apiError.ErrMsg)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w, body: %s", err, string(body))
	}

	c.AccessToken = tokenResp.AccessToken
	c.RefreshToken = tokenResp.RefreshToken
	c.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	c.UID = tokenResp.UID

	log.Printf("Successfully authenticated user: %s", username)
	return &tokenResp, nil
}

func (c *TTLockClient) ListLocks(pageNo, pageSize int, groupID int, alias string, userId int) (*LocksResponse, error) {
	user, err := db.GetUserByID(userId)
	fmt.Println(user.ID, user.Name, user.AccessToken)
	//if time.Now().After(c.ExpiresAt) {
	//	err := c.refreshToken()
	//	if err != nil {
	//		return nil, fmt.Errorf("token refresh failed: %w", err)
	//	}
	//}

	payload := fmt.Sprintf(
		"clientId=%s&accessToken=%s&pageNo=%s&pageSize=%s&date=%s",
		clientID,
		user.AccessToken,
		strconv.Itoa(pageNo),
		strconv.Itoa(pageSize),
		strconv.FormatInt(time.Now().UnixMilli(), 10),
	)

	urlStr := fmt.Sprintf("%s/lock/list?%s", baseURL, payload)
	log.Printf("Request URL: %s", urlStr)

	req, err := http.NewRequest(
		"GET",
		urlStr,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("Auth response status: %d, body: %s", resp.StatusCode, string(body))

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil, fmt.Errorf("unexpected content type: %s, body: %s", contentType, string(body))
	}

	if resp.StatusCode != http.StatusOK {
		var apiError struct {
			ErrCode int    `json:"errcode"`
			ErrMsg  string `json:"errmsg"`
		}
		if err := json.Unmarshal(body, &apiError); err != nil {
			return nil, fmt.Errorf("failed to parse error response (status %d): %w, body: %s",
				resp.StatusCode, err, string(body))
		}
		return nil, fmt.Errorf("API error %d: %s", apiError.ErrCode, apiError.ErrMsg)
	}

	var locksResp LocksResponse
	if err := json.Unmarshal(body, &locksResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w, body: %s", err, string(body))
	}

	return &locksResp, nil
}

func (c *TTLockClient) LockControl(lockID int, action string) error {
	url := fmt.Sprintf("%s/lock/control", baseURL)

	data := map[string]interface{}{
		"clientId":    clientID,
		"accessToken": c.AccessToken,
		"lockId":      lockID,
		"controlType": action,
		"date":        time.Now().Unix(),
	}

	jsonData, _ := json.Marshal(data)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func (c *TTLockClient) doRequest(method, urlStr string, params url.Values) ([]byte, error) {
	if time.Now().After(c.ExpiresAt) {
		if err := c.refreshToken(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
	}

	fullURL := fmt.Sprintf("%s?%s", urlStr, params.Encode())

	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			ErrCode int    `json:"errcode"`
			ErrMsg  string `json:"errmsg"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, fmt.Errorf("TTLock API error %d: %s", errorResp.ErrCode, errorResp.ErrMsg)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

func (c *TTLockClient) GetLockRecords(lockID int, startDate, endDate int64) (*LockRecordsResponse, error) {
	params := url.Values{}
	params.Set("clientId", clientID)
	params.Set("accessToken", c.AccessToken)
	params.Set("lockId", strconv.Itoa(lockID))
	params.Set("pageNo", "1")
	params.Set("pageSize", "200")
	params.Set("date", strconv.FormatInt(time.Now().Unix()*1000, 10))

	if startDate > 0 {
		params.Set("startDate", strconv.FormatInt(startDate, 10))
	}
	if endDate > 0 {
		params.Set("endDate", strconv.FormatInt(endDate, 10))
	}

	urlStr := fmt.Sprintf("%s/lockRecord/list", baseURL)
	respBody, err := c.doRequest("GET", urlStr, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get lock records: %w", err)
	}

	var result LockRecordsResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal lock records: %w", err)
	}

	return &result, nil
}

func (c *TTLockClient) ConfigurePassageMode(lockID int, passageMode int, configType int) error {
	if time.Now().After(c.ExpiresAt) {
		if err := c.refreshToken(); err != nil {
			return fmt.Errorf("token refresh failed: %w", err)
		}
	}

	data := url.Values{}
	data.Set("clientId", clientID)
	data.Set("accessToken", c.AccessToken)
	data.Set("lockId", strconv.Itoa(lockID))
	data.Set("passageMode", strconv.Itoa(passageMode))

	//if cyclicConfig != "" {
	//	data.Set("cyclicConfig", cyclicConfig)
	//}
	//
	//if autoUnlock > 0 {
	//	data.Set("autoUnlock", strconv.Itoa(autoUnlock))
	//}

	data.Set("type", strconv.Itoa(configType))
	data.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	resp, err := http.PostForm(baseURL+"/lock/configurePassageMode", data)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if result.ErrCode != 0 {
		return fmt.Errorf("TTLock API error %d: %s", result.ErrCode, result.ErrMsg)
	}

	return nil
}

func (c *TTLockClient) GetPassageMode(lockID int) (*PassageModeConfig, error) {
	if time.Now().After(c.ExpiresAt) {
		if err := c.refreshToken(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
	}

	params := url.Values{}
	params.Set("clientId", clientID)
	params.Set("accessToken", c.AccessToken)
	params.Set("lockId", strconv.Itoa(lockID))
	params.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	urlStr := fmt.Sprintf("%s/lock/getPassageModeConfiguration?%s", baseURL, params.Encode())
	resp, err := http.Get(urlStr)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			ErrCode int    `json:"errcode"`
			ErrMsg  string `json:"errmsg"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, fmt.Errorf("TTLock API error %d: %s", errorResp.ErrCode, errorResp.ErrMsg)
	}

	var config PassageModeConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &config, nil
}

func (c *TTLockClient) refreshToken() error {
	url := fmt.Sprintf("%s/oauth2/token?grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s",
		baseURL, clientID, clientSecret, c.RefreshToken)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	c.AccessToken = result.AccessToken
	c.RefreshToken = result.RefreshToken
	c.ExpiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)

	return nil
}

func (c *TTLockClient) SendEKey(lockID int, receiverUsername, keyName string,
	startDate, endDate time.Time, remarks string) (int, error) {

	if time.Now().After(c.ExpiresAt) {
		if err := c.refreshToken(); err != nil {
			return 0, fmt.Errorf("token refresh failed: %w", err)
		}
	}

	data := url.Values{}
	data.Set("clientId", clientID)
	data.Set("accessToken", c.AccessToken)
	data.Set("lockId", strconv.Itoa(lockID))
	data.Set("receiverUsername", receiverUsername)
	data.Set("keyName", keyName)
	data.Set("startDate", strconv.FormatInt(startDate.UnixMilli(), 10))
	data.Set("endDate", strconv.FormatInt(endDate.UnixMilli(), 10))
	data.Set("createUser", "1") // Автосоздание аккаунта если не существует
	data.Set("remarks", remarks)
	data.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	resp, err := http.PostForm(baseURL+"/v3/key/send", data)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			ErrCode int    `json:"errcode"`
			ErrMsg  string `json:"errmsg"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return 0, fmt.Errorf("failed to decode error response: %w", err)
		}
		return 0, fmt.Errorf("TTLock API error %d: %s", errorResp.ErrCode, errorResp.ErrMsg)
	}

	var result struct {
		KeyID int `json:"keyId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.KeyID, nil
}

func (c *TTLockClient) ChangeKeyPeriod(keyID int, startDate, endDate time.Time) error {
	if time.Now().After(c.ExpiresAt) {
		if err := c.refreshToken(); err != nil {
			return fmt.Errorf("token refresh failed: %w", err)
		}
	}

	data := url.Values{}
	data.Set("clientId", clientID)
	data.Set("accessToken", c.AccessToken)
	data.Set("keyId", strconv.Itoa(keyID))
	data.Set("startDate", strconv.FormatInt(startDate.UnixMilli(), 10))
	data.Set("endDate", strconv.FormatInt(endDate.UnixMilli(), 10))
	data.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	resp, err := http.PostForm(baseURL+"/v3/key/changePeriod", data)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if result.ErrCode != 0 {
		return fmt.Errorf("TTLock API error %d: %s", result.ErrCode, result.ErrMsg)
	}

	return nil
}

func (c *TTLockClient) FreezeKey(keyID int) error {
	if time.Now().After(c.ExpiresAt) {
		if err := c.refreshToken(); err != nil {
			return fmt.Errorf("token refresh failed: %w", err)
		}
	}

	data := url.Values{}
	data.Set("clientId", clientID)
	data.Set("accessToken", c.AccessToken)
	data.Set("keyId", strconv.Itoa(keyID))
	data.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	resp, err := http.PostForm(baseURL+"/v3/key/freeze", data)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if result.ErrCode != 0 {
		return fmt.Errorf("TTLock API error %d: %s", result.ErrCode, result.ErrMsg)
	}

	return nil
}

func (c *TTLockClient) ListKeys(lockID, pageNo, pageSize, orderBy int, searchStr string) (*KeysResponse, error) {
	if time.Now().After(c.ExpiresAt) {
		if err := c.refreshToken(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
	}

	params := url.Values{}
	params.Add("clientId", clientID)
	params.Add("accessToken", c.AccessToken)
	params.Add("lockId", strconv.Itoa(lockID))
	params.Add("pageNo", strconv.Itoa(pageNo))
	params.Add("pageSize", strconv.Itoa(pageSize))
	params.Add("orderBy", strconv.Itoa(orderBy))
	params.Add("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	if searchStr != "" {
		params.Add("searchStr", searchStr)
	}

	url := fmt.Sprintf("%s/v3/lock/listKey?%s", baseURL, params.Encode())

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			ErrCode int    `json:"errcode"`
			ErrMsg  string `json:"errmsg"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, fmt.Errorf("TTLock API error %d: %s", errorResp.ErrCode, errorResp.ErrMsg)
	}

	var keysResp KeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &keysResp, nil
}
