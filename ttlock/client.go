package ttlock

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Константы, которые могут быть определены на этапе компиляции
const (
	baseURL = "https://euapi.ttlock.com/v3"
)

var (
	clientID     string
	clientSecret string
)

func init() {
	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
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

func NewClient() *TTLockClient {
	return &TTLockClient{}
}

func (c *TTLockClient) RegisterUser(username, password string) (string, error) {
	hashedPassword := fmt.Sprintf("%x", md5.Sum([]byte(password)))

	data := url.Values{}
	data.Set("clientId", clientID)
	data.Set("clientSecret", clientSecret)
	data.Set("username", username)
	data.Set("password", hashedPassword)
	data.Set("date", fmt.Sprintf("%d", time.Now().UnixMilli()))

	resp, err := http.PostForm(baseURL+"/user/register", data)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			ErrCode int    `json:"errcode"`
			ErrMsg  string `json:"errmsg"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return "", fmt.Errorf("failed to decode error response: %w", err)
		}
		return "", fmt.Errorf("TTLock API error %d: %s", errorResp.ErrCode, errorResp.ErrMsg)
	}

	var result struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Username, nil
}

func (c *TTLockClient) Authenticate(username, password string) (*TokenResponse, error) {
	hashedPassword := fmt.Sprintf("%x", md5.Sum([]byte(password)))

	data := url.Values{}
	data.Set("clientId", clientID)
	data.Set("clientSecret", clientSecret)
	data.Set("username", username)
	data.Set("password", hashedPassword)

	req, err := http.NewRequest(
		"POST",
		baseURL+"/oauth2/token",
		bytes.NewBufferString(data.Encode()),
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

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	c.AccessToken = tokenResp.AccessToken
	c.RefreshToken = tokenResp.RefreshToken
	c.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	c.UID = tokenResp.UID

	return &tokenResp, nil
}

func (c *TTLockClient) ListLocks(pageNo, pageSize int, groupID int, alias string) (*LocksResponse, error) {
	if time.Now().After(c.ExpiresAt) {
		if err := c.refreshToken(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
	}

	params := url.Values{}
	params.Add("clientId", clientID)
	params.Add("accessToken", c.AccessToken)
	params.Add("pageNo", strconv.Itoa(pageNo))
	params.Add("pageSize", strconv.Itoa(pageSize))
	params.Add("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	if groupID != 0 {
		params.Add("groupId", strconv.Itoa(groupID))
	}
	if alias != "" {
		params.Add("lockAlias", alias)
	}

	url := fmt.Sprintf("%s/v3/lock/list?%s", baseURL, params.Encode())

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

	var locksResp LocksResponse
	if err := json.NewDecoder(resp.Body).Decode(&locksResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
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
