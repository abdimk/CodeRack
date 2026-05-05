package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/abdimk/coderack/config"
)

// ---------------------------------------------------------------------------
// Qwen Coder API
// ---------------------------------------------------------------------------

func CallQwenCoderAPI(prompt string) (string, error) {
	bearerToken := config.HardcodedQwenBearerToken
	if config.QwenBearerToken != "" {
		bearerToken = config.QwenBearerToken
	}

	payload := map[string]interface{}{
		"model": "qwen3-coder-plus",
		"messages": []map[string]string{
			{"role": "code", "content": prompt},
		},
		"stream": false,
	}
	b, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", "https://qwen.aikit.club/v1/chat/completions", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("Qwen API request failed (%d): %v", resp.StatusCode, result)
	}

	// Extract choices[0].message.content
	choices, _ := result["choices"].([]interface{})
	if len(choices) == 0 {
		return "", nil
	}
	choice, _ := choices[0].(map[string]interface{})
	message, _ := choice["message"].(map[string]interface{})
	content, _ := message["content"].(string)
	return strings.TrimSpace(content), nil
}

// ---------------------------------------------------------------------------
// PR summarisation
// ---------------------------------------------------------------------------

type PRContext struct {
	Title        string
	Author       string
	Body         string
	BaseBranch   string
	HeadBranch   string
	ChangedFiles int
	Additions    int
	Deletions    int
	FilesSummary string
}

func SummarizePullRequestWithQwenCoder(prContext PRContext) (string, error) {
	lines := []string{
		"Summarize this GitHub pull request concisely and practically, then give a clear recommendation.",
		"Structure your response with these sections:",
		"1) What changed",
		"2) Risk areas",
		"3) Suggested review focus",
		"4) Suggested tests",
		"5) Recommendation",
		"",
		fmt.Sprintf("Title: %s", prContext.Title),
		fmt.Sprintf("Author: %s", prContext.Author),
		fmt.Sprintf("Base: %s", prContext.BaseBranch),
		fmt.Sprintf("Head: %s", prContext.HeadBranch),
		fmt.Sprintf("Changed files: %d", prContext.ChangedFiles),
		fmt.Sprintf("Additions: %d", prContext.Additions),
		fmt.Sprintf("Deletions: %d", prContext.Deletions),
		"",
		"Description:",
		func() string {
			if prContext.Body == "" {
				return "(no description)"
			}
			return prContext.Body
		}(),
		"",
		"Files changed:",
		func() string {
			if prContext.FilesSummary == "" {
				return "(no files listed)"
			}
			return prContext.FilesSummary
		}(),
	}

	prompt := strings.Join(lines, "\n")
	summary, err := CallQwenCoderAPI(prompt)
	if err != nil {
		return "", err
	}
	if summary == "" {
		return "Qwen Coder returned no summary text.", nil
	}
	return summary, nil
}
