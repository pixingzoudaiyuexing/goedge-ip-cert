package goedge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/security"
)

const maxResponseSize = 32 << 20

type Client struct {
	baseURL     *url.URL
	httpClient  *http.Client
	credentials CredentialProvider
	mu          sync.Mutex
	token       string
	expiresAt   time.Time
}

func NewClient(endpoint string, httpClient *http.Client, credentials CredentialProvider) (*Client, error) {
	baseURL, err := url.Parse(endpoint)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, errors.New("无效的 GoEdge endpoint")
	}
	if httpClient == nil || credentials == nil {
		return nil, errors.New("GoEdge HTTP client/credentials 不能为空")
	}
	return &Client{baseURL: baseURL, httpClient: httpClient, credentials: credentials}, nil
}

type apiCode int

func (c *apiCode) UnmarshalJSON(data []byte) error {
	var number int
	if err := json.Unmarshal(data, &number); err == nil {
		*c = apiCode(number)
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	value, err := strconv.Atoi(text)
	if err != nil {
		return err
	}
	*c = apiCode(value)
	return nil
}

type envelope struct {
	Code    apiCode         `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (c *Client) call(ctx context.Context, path string, request, response any) error {
	return c.callAttempt(ctx, path, request, response, true)
}

func (c *Client) callAttempt(ctx context.Context, path string, request, response any, allowRefresh bool) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	env, err := c.post(ctx, path, request, token)
	if err != nil {
		return err
	}
	if int(env.Code) != 200 {
		message := safeAPIMessage(env.Message, token)
		if allowRefresh && strings.Contains(strings.ToLower(env.Message), "token") {
			c.invalidateToken()
			return c.callAttempt(ctx, path, request, response, false)
		}
		if strings.Contains(strings.ToLower(env.Message), "access token") || strings.Contains(strings.ToLower(env.Message), "permission") {
			return fmt.Errorf("%w: %s", ErrAuthentication, message)
		}
		return fmt.Errorf("GoEdge API %s: %s", path, message)
	}
	if response == nil {
		return nil
	}
	if len(env.Data) == 0 || bytes.Equal(env.Data, []byte("null")) {
		return fmt.Errorf("%w: %s data 为空", ErrUnexpectedResponse, path)
	}
	if err := json.Unmarshal(env.Data, response); err != nil {
		return fmt.Errorf("%w: 解析 %s data: %v", ErrUnexpectedResponse, path, err)
	}
	return nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Add(time.Minute).Before(c.expiresAt) {
		return c.token, nil
	}
	credentials, err := c.credentials.Credentials()
	if err != nil {
		return "", err
	}
	if credentials.AccessKeyID == "" || credentials.AccessKey == "" || (credentials.IdentityType != "admin" && credentials.IdentityType != "user") {
		return "", errors.New("GoEdge credentials 不完整")
	}
	var result struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	env, err := c.post(ctx, "/APIAccessTokenService/getAPIAccessToken", map[string]string{
		"type": credentials.IdentityType, "accessKeyId": credentials.AccessKeyID, "accessKey": credentials.AccessKey,
	}, "")
	if err != nil {
		return "", err
	}
	if int(env.Code) != 200 {
		message := safeAPIMessage(env.Message, credentials.AccessKeyID, credentials.AccessKey)
		return "", fmt.Errorf("%w: %s", ErrAuthentication, message)
	}
	if err := json.Unmarshal(env.Data, &result); err != nil || result.Token == "" || result.ExpiresAt <= time.Now().Unix() {
		return "", fmt.Errorf("%w: token 响应无效", ErrUnexpectedResponse)
	}
	c.token = result.Token
	c.expiresAt = time.Unix(result.ExpiresAt, 0)
	return c.token, nil
}

func safeAPIMessage(message string, secrets ...string) string {
	message = security.NewRedactor(secrets...).Redact(message)
	const maxRunes = 1024
	runes := []rune(message)
	if len(runes) > maxRunes {
		message = string(runes[:maxRunes]) + "..."
	}
	return message
}

func (c *Client) post(ctx context.Context, path string, body any, token string) (envelope, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return envelope{}, err
	}
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return envelope{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("X-Edge-Access-Token", token)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return envelope{}, fmt.Errorf("GoEdge HTTP %s: %w", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return envelope{}, fmt.Errorf("GoEdge HTTP %s status=%d", path, response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return envelope{}, err
	}
	if len(data) > maxResponseSize {
		return envelope{}, fmt.Errorf("%w: response 超过 32 MiB", ErrUnexpectedResponse)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return envelope{}, fmt.Errorf("%w: 无效 envelope", ErrUnexpectedResponse)
	}
	return env, nil
}

func (c *Client) invalidateToken() {
	c.mu.Lock()
	c.token = ""
	c.expiresAt = time.Time{}
	c.mu.Unlock()
}
