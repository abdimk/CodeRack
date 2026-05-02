package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/abdimk/coderack/config"
)

// ---------------------------------------------------------------------------
// Telegram
// ---------------------------------------------------------------------------

func sendTelegramMessage(text string) {
	if config.TelegramBotToken == "" || config.TelegramChatId == "" {
		log.Println("Telegram notification skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing.")
		return
	}

	maxLength := 4000
	message := text
	if len(message) > maxLength {
		message = message[:maxLength-3] + "..."
	}

	payload := map[string]interface{}{
		"chat_id":                  config.TelegramChatId,
		"text":                     message,
		"disable_web_page_preview": true,
	}
	b, _ := json.Marshal(payload)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.TelegramBotToken)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Printf("Failed to send Telegram message: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Failed to send Telegram message (%d): %s", resp.StatusCode, string(bodyBytes))
	}
}
