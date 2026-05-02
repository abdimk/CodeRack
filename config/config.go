package config

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Configuration
var (
	AppID                    int64
	WebhookSecret            string
	PrivateKeyPEM            string
	QwenBearerToken          string
	HardcodedQwenBearerToken string
	TelegramBotToken         string
	TelegramChatId           string
)


// Private-Key helps 

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
	// Decode PEM → raw DER → parse RSA key
	pemBlock := PrivateKeyPEM
	// strip header/footer and newlines to get base64
	pemBlock = strings.TrimPrefix(pemBlock, "-----BEGIN RSA PRIVATE KEY-----")
	pemBlock = strings.TrimSuffix(pemBlock, "-----END RSA PRIVATE KEY-----")
	pemBlock = strings.TrimSpace(pemBlock)
	pemBlock = strings.ReplaceAll(pemBlock, "\n", "")

	der, err := base64.StdEncoding.DecodeString(pemBlock)
	if err != nil {
		return "", fmt.Errorf("base64 decode private key: %w", err)
	}

	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(PrivateKeyPEM))
	if err != nil {
		// fall back: try to parse raw DER
		_ = der
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
