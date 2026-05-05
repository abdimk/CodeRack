package main

import (
	"log"
	"os"

	"github.com/abdimk/coderack/config"
	"github.com/abdimk/coderack/internal"
)

func main() {
	
	config.LoadConfig()

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	qwenStatus := "NOT configured"
	if config.QwenBearerToken != "" || config.HardcodedQwenBearerToken != "" {
		qwenStatus = "configured"
	}
	telegramStatus := "NOT configured"
	if config.TelegramBotToken != "" && config.TelegramChatId != "" {
		telegramStatus = "configured"
	}

	log.Printf("Qwen API: %s", qwenStatus)
	log.Printf("Telegram: %s", telegramStatus)

	if err := internal.StartServer(port); err != nil {
		log.Fatal(err)
	}
}
