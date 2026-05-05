package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/abdimk/coderack/config"
)

// ---------------------------------------------------------------------------
// Telegram
// ---------------------------------------------------------------------------

func SendTelegramMessage(text string) {
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

// ---------------------------------------------------------------------------
// Telegram message builder
// ---------------------------------------------------------------------------

func ExtractSummarySection(summaryText, sectionTitle string) string {
	// Escape regex special chars
	escaped := regexp.QuoteMeta(sectionTitle)
	pattern := fmt.Sprintf(`(?i)(?:^|\n)%s\s*:?\s*\n([\s\S]*?)(?:\n\d+\)|\n[A-Z][^\n]*:\s*\n|$)`, escaped)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(summaryText)
	if len(match) >= 2 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

func Trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func BuildTelegramPrSummary(owner, repo string, pullNumber int, prURL, eventType string, prContext PRContext, summaryText string, hasVulnerabilities bool) string {
	recommendation := ExtractSummarySection(summaryText, "5) Recommendation")
	if recommendation == "" {
		recommendation = ExtractSummarySection(summaryText, "Recommendation")
	}
	if recommendation == "" {
		recommendation = "See PR comment for recommendation details."
	}

	topFiles := "(no files listed)"
	if prContext.FilesSummary != "" {
		fileLines := strings.Split(prContext.FilesSummary, "\n")
		limit := 5
		if len(fileLines) < limit {
			limit = len(fileLines)
		}
		topFiles = strings.Join(fileLines[:limit], "\n")
	}

	securityLine := "✅ Security: No critical security issues detected."
	if hasVulnerabilities {
		securityLine = "⚠️ Security: Potential vulnerabilities detected."
	}

	prFlag := "✅"
	if hasVulnerabilities {
		prFlag = "⚠️"
	}

	parts := []string{
		fmt.Sprintf("🔔 PR %s %s", strings.ToUpper(eventType), prFlag),
		fmt.Sprintf("%s/%s #%d", owner, repo, pullNumber),
		fmt.Sprintf("Title: %s", prContext.Title),
		fmt.Sprintf("Author: @%s", prContext.Author),
		fmt.Sprintf("Branches: %s <- %s", prContext.BaseBranch, prContext.HeadBranch),
		fmt.Sprintf("Changes: %d files, +%d / -%d", prContext.ChangedFiles, prContext.Additions, prContext.Deletions),
		prURL,
		"",
		"📝 Summary:",
		Trunc(summaryText, 900),
		"",
		"✅ Recommendation:",
		Trunc(recommendation, 500),
		"",
		"📂 Top changed files:",
		topFiles,
		"",
		securityLine,
	}

	return strings.Join(parts, "\n")
}

func BuildSecurityIssueTelegramMessage(owner, repo string, issueNumber, pullNumber int, issueURL string) string {
	return strings.Join([]string{
		"🚨 Security issue created",
		fmt.Sprintf("%s/%s#%d", owner, repo, issueNumber),
		fmt.Sprintf("From PR #%d", pullNumber),
		issueURL,
		"",
		"Reason:",
		"Potential vulnerabilities were detected during automated PR analysis.",
	}, "\n")
}
