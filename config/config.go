package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

// Configuration
var (
	AppID                    int64
	WebhookSecret            string
	PrivateKeyPEM            string
	PrivateKeyPath           string
	QwenBearerToken          string
	HardcodedQwenBearerToken string
	TelegramBotToken         string
	TelegramChatId           string
)

func LoadConfig() {
	// Load .env (tolerates malformed/bare lines)
	if err := loadEnvFile(".env"); err != nil {
		if os.IsNotExist(err) {
			log.Println("No .env file found, reading from environment")
		} else {
			log.Printf("Warning: could not fully parse .env: %v", err)
		}
	}

	// Parse config
	appIDStr := os.Getenv("APP_ID")
	if appIDStr == "" {
		log.Fatal("Missing APP_ID in environment")
	}
	fmt.Sscanf(appIDStr, "%d", &AppID)

	WebhookSecret = os.Getenv("WEBHOOK_SECRET")
	PrivateKeyPath = os.Getenv("PRIVATE_KEY_PATH")
	keyPEM, err := loadPrivateKeyPEM()
	if err != nil {
		log.Fatal(err)
	}
	PrivateKeyPEM = keyPEM
	QwenBearerToken = os.Getenv("QWEN_BEARER_TOKEN")
	TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	TelegramChatId = os.Getenv("TELEGRAM_CHAT_ID")

	if AppID == 0 || WebhookSecret == "" || PrivateKeyPEM == "" {
		log.Fatal("Missing APP_ID, WEBHOOK_SECRET, or PRIVATE_KEY in environment")
	}
}

// loadEnvFile reads the .env file and loads only valid KEY=VALUE lines,
// silently skipping bare values (e.g. stray JWT tokens) that have no key.
func loadEnvFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	var cleaned strings.Builder
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		// Keep blank lines, comments, and valid KEY=VALUE lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.Contains(trimmed, "=") {
			cleaned.WriteString(line + "\n")
		} else {
			log.Printf(".env: skipping malformed line (no KEY=): %.40s...", trimmed)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	envMap, err := godotenv.Unmarshal(cleaned.String())
	if err != nil {
		return err
	}
	for k, v := range envMap {
		if os.Getenv(k) == "" { // don't override existing env vars
			os.Setenv(k, v)
		}
	}
	return nil
}

// Private-Key helps

func loadPrivateKeyPEM() (string, error) {
	rawKey := os.Getenv("PRIVATE_KEY")
	if strings.TrimSpace(rawKey) != "" {
		key := normalizePrivateKey(rawKey)
		if _, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(key)); err == nil {
			return key, nil
		}
	}

	if strings.TrimSpace(PrivateKeyPath) != "" {
		content, err := os.ReadFile(PrivateKeyPath)
		if err != nil {
			return "", fmt.Errorf("failed to read PRIVATE_KEY_PATH %q: %w", PrivateKeyPath, err)
		}
		key := normalizePrivateKey(string(content))
		if _, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(key)); err != nil {
			return "", fmt.Errorf("invalid private key in PRIVATE_KEY_PATH %q: %w", PrivateKeyPath, err)
		}
		return key, nil
	}

	if strings.TrimSpace(rawKey) != "" {
		return "", fmt.Errorf("PRIVATE_KEY is set but invalid/truncated; provide full key or set PRIVATE_KEY_PATH to a .pem file")
	}

	return "", fmt.Errorf("missing private key: set PRIVATE_KEY or PRIVATE_KEY_PATH")
}

func normalizePrivateKey(raw string) string {
	if raw == "" {
		return ""
	}
	key := strings.ReplaceAll(raw, `\n`, "\n")
	key = strings.TrimSpace(key)

	if strings.Contains(key, "BEGIN") && strings.Contains(key, "PRIVATE KEY") {
		return key
	}

	// strip all whitespace, then wrap at 64 chars
	re := regexp.MustCompile(`\s+`)
	cleaned := re.ReplaceAllString(key, "")
	wrapped := wrapAt64(cleaned)
	return "-----BEGIN RSA PRIVATE KEY-----\n" + wrapped + "\n-----END RSA PRIVATE KEY-----"
}

func wrapAt64(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i += 64 {
		end := i + 64
		if end > len(s) {
			end = len(s)
		}
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(s[i:end])
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// GitHub App JWT
// ---------------------------------------------------------------------------

func GenerateJWT() (string, error) {
	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(PrivateKeyPEM))
	if err != nil {
		return "", fmt.Errorf("parse RSA private key: %w", err)
	}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
		Issuer:    fmt.Sprintf("%d", AppID),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(rsaKey)
}
