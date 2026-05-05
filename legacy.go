package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

var (
	appID                    int64
	webhookSecret            string
	privateKeyPEM            string
	qwenBearerToken          string
	hardcodedQwenBearerToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjI5MjIwNzM3LTM1YTktNDg0ZC04ODc0LTU1YjAwN2Y4NzFmMCIsImxhc3RfcGFzc3dvcmRfY2hhbmdlIjoxNzczNjU5OTQ1LCJleHAiOjE3Nzc3MDQ3ODh9.Na6vP3SkA1zb6L6gOkL9wLBz7b12Z0nBNO52Zzo1RP8"
	telegramBotToken         string
	telegramChatId           string
)

// ---------------------------------------------------------------------------
// Private-key helpers (mirrors normalizePrivateKey in JS)
// ---------------------------------------------------------------------------

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

func generateJWT() (string, error) {
	// Decode PEM → raw DER → parse RSA key
	pemBlock := privateKeyPEM
	// strip header/footer and newlines to get base64
	pemBlock = strings.TrimPrefix(pemBlock, "-----BEGIN RSA PRIVATE KEY-----")
	pemBlock = strings.TrimSuffix(pemBlock, "-----END RSA PRIVATE KEY-----")
	pemBlock = strings.TrimSpace(pemBlock)
	pemBlock = strings.ReplaceAll(pemBlock, "\n", "")

	der, err := base64.StdEncoding.DecodeString(pemBlock)
	if err != nil {
		return "", fmt.Errorf("base64 decode private key: %w", err)
	}

	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil {
		// fall back: try to parse raw DER
		_ = der
		return "", fmt.Errorf("parse RSA private key: %w", err)
	}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
		Issuer:    fmt.Sprintf("%d", appID),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(rsaKey)
}

// ---------------------------------------------------------------------------
// GitHub REST helpers
// ---------------------------------------------------------------------------

type Installation struct {
	ID int64 `json:"id"`
}

func getInstallationToken(installationID int64) (string, error) {
	jwtToken, err := generateJWT()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Token, nil
}

// githubGet performs a GET request authenticated with the installation token.
func githubGet(token, url string, out interface{}) error {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// githubPost performs a POST request authenticated with the installation token.
func githubPost(token, url string, body interface{}, out interface{}) (int, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

// githubPatch performs a PATCH request (for updating issues).
func githubPatch(token, url string, body interface{}, out interface{}) (int, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("PATCH", url, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

// ---------------------------------------------------------------------------
// GitHub paginate: list PR files
// ---------------------------------------------------------------------------

type PRFile struct {
	Filename  string `json:"filename"`
	Status    string `json:"status"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Patch     string `json:"patch"`
}

func listPRFiles(token, owner, repo string, pullNumber int) ([]PRFile, error) {
	var all []PRFile
	page := 1
	for {
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d/files?per_page=100&page=%d", owner, repo, pullNumber, page)
		var files []PRFile
		if err := githubGet(token, url, &files); err != nil {
			return nil, err
		}
		all = append(all, files...)
		if len(files) < 100 {
			break
		}
		page++
	}
	return all, nil
}

// ---------------------------------------------------------------------------
// GitHub issue / comment helpers
// ---------------------------------------------------------------------------

func isIntegrationPermissionError(statusCode int, body string) bool {
	return statusCode == 403 && strings.Contains(body, "Resource not accessible by integration")
}

func safeCreateIssueComment(token, owner, repo string, issueNumber int, body string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d/comments", owner, repo, issueNumber)
	payload := map[string]string{"body": body}

	var result map[string]interface{}
	status, err := githubPost(token, url, payload, &result)
	if err != nil {
		return err
	}
	if status == 403 {
		resp403Body, _ := json.Marshal(result)
		if isIntegrationPermissionError(status, string(resp403Body)) {
			log.Println("Missing GitHub App permission: set Issues to Read and write, then reinstall the app.")
			return nil
		}
	}
	return nil
}

type GitHubIssue struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

func createGitHubIssue(token, owner, repo string, title, body string, labels []string) (*GitHubIssue, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", owner, repo)
	payload := map[string]interface{}{
		"title":  title,
		"body":   body,
		"labels": labels,
	}
	var issue GitHubIssue
	status, err := githubPost(token, url, payload, &issue)
	if err != nil {
		return nil, err
	}
	if status == 403 {
		log.Println("Cannot create issue: Missing GitHub App permission (Issues: Read and write)")
		return nil, fmt.Errorf("403 forbidden creating issue")
	}
	log.Printf("Created security issue #%d for %s/%s", issue.Number, owner, repo)
	return &issue, nil
}

func closeGitHubIssue(token, owner, repo string, issueNumber int) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d", owner, repo, issueNumber)
	payload := map[string]string{"state": "closed"}
	_, err := githubPatch(token, url, payload, nil)
	return err
}

// ---------------------------------------------------------------------------
// Telegram
// ---------------------------------------------------------------------------

func sendTelegramMessage(text string) {
	if telegramBotToken == "" || telegramChatId == "" {
		log.Println("Telegram notification skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing.")
		return
	}

	maxLength := 4000
	message := text
	if len(message) > maxLength {
		message = message[:maxLength-3] + "..."
	}

	payload := map[string]interface{}{
		"chat_id":                  telegramChatId,
		"text":                     message,
		"disable_web_page_preview": true,
	}
	b, _ := json.Marshal(payload)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramBotToken)
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
// Qwen Coder API
// ---------------------------------------------------------------------------

func callQwenCoderAPI(prompt string) (string, error) {
	bearerToken := hardcodedQwenBearerToken
	if qwenBearerToken != "" {
		bearerToken = qwenBearerToken
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

func summarizePullRequestWithQwenCoder(prContext PRContext) (string, error) {
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
	summary, err := callQwenCoderAPI(prompt)
	if err != nil {
		return "", err
	}
	if summary == "" {
		return "Qwen Coder returned no summary text.", nil
	}
	return summary, nil
}

// ---------------------------------------------------------------------------
// Security analysis
// ---------------------------------------------------------------------------

type SecurityResult struct {
	HasVulnerabilities bool
	Report             string
}

func analyzeSecurityVulnerabilities(files []PRFile) SecurityResult {
	if qwenBearerToken == "" {
		return SecurityResult{false, "Security analysis skipped: QWEN_BEARER_TOKEN not configured."}
	}
	if len(files) == 0 {
		return SecurityResult{false, "Security analysis skipped: no changed files were detected in this PR event."}
	}

	// Build content for up to 20 files
	var fileContents []string
	limit := 20
	if len(files) < limit {
		limit = len(files)
	}
	for _, f := range files[:limit] {
		patch := f.Patch
		fileContents = append(fileContents, fmt.Sprintf("### File: %s (Status: %s)\n```diff\n%s\n```", f.Filename, f.Status, patch))
	}
	filesContent := strings.Join(fileContents, "\n\n")

	lines := []string{
		"Analyze the following code changes for security vulnerabilities.",
		"Look for common security issues like:",
		"- SQL injection",
		"- XSS (Cross-Site Scripting)",
		"- CSRF (Cross-Site Request Forgery)",
		"- Insecure authentication/authorization",
		"- Hardcoded secrets or API keys",
		"- Path traversal",
		"- Command injection",
		"- Insecure deserialization",
		"- Sensitive data exposure",
		"- Missing input validation",
		"- Weak cryptography",
		"",
		"For each vulnerability found, provide:",
		"- **Severity**: Critical, High, Medium, Low",
		"- **File**: The file path",
		"- **Issue**: Description of the vulnerability",
		"- **Evidence**: The problematic code snippet",
		"- **Recommendation**: How to fix it",
		"",
		"If no vulnerabilities are found, clearly state that.",
		"Be precise and avoid false positives.",
		"",
		"Code changes to analyze:",
		filesContent,
	}
	prompt := strings.Join(lines, "\n")

	analysis, err := callQwenCoderAPI(prompt)
	if err != nil {
		log.Println("Security analysis failed:", err)
		return SecurityResult{false, "Security analysis failed due to API error."}
	}

	lower := strings.ToLower(analysis)
	hasVulnerabilities := strings.Contains(lower, "critical") ||
		strings.Contains(lower, "high") ||
		strings.Contains(lower, "vulnerability") ||
		strings.Contains(lower, "security issue") ||
		!strings.Contains(lower, "no vulnerabilities")

	report := analysis
	if report == "" {
		report = "No security issues detected."
	}

	return SecurityResult{hasVulnerabilities, report}
}

// ---------------------------------------------------------------------------
// Telegram message builder
// ---------------------------------------------------------------------------

func extractSummarySection(summaryText, sectionTitle string) string {
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

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func buildTelegramPrSummary(owner, repo string, pullNumber int, prURL, eventType string, prContext PRContext, summaryText string, hasVulnerabilities bool) string {
	recommendation := extractSummarySection(summaryText, "5) Recommendation")
	if recommendation == "" {
		recommendation = extractSummarySection(summaryText, "Recommendation")
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
		trunc(summaryText, 900),
		"",
		"✅ Recommendation:",
		trunc(recommendation, 500),
		"",
		"📂 Top changed files:",
		topFiles,
		"",
		securityLine,
	}

	return strings.Join(parts, "\n")
}

// ---------------------------------------------------------------------------
// Webhook payload types (minimal — only fields we actually use)
// ---------------------------------------------------------------------------

type WebhookUser struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

type WebhookRepo struct {
	Name     string      `json:"name"`
	FullName string      `json:"full_name"`
	Owner    WebhookUser `json:"owner"`
	HTMLURL  string      `json:"html_url"`
}

type WebhookBranch struct {
	Ref string `json:"ref"`
}

type WebhookPR struct {
	Number       int           `json:"number"`
	Title        string        `json:"title"`
	Body         string        `json:"body"`
	HTMLURL      string        `json:"html_url"`
	User         WebhookUser   `json:"user"`
	Base         WebhookBranch `json:"base"`
	Head         WebhookBranch `json:"head"`
	ChangedFiles int           `json:"changed_files"`
	Additions    int           `json:"additions"`
	Deletions    int           `json:"deletions"`
}

type WebhookComment struct {
	Body    string      `json:"body"`
	User    WebhookUser `json:"user"`
	HTMLURL string      `json:"html_url"`
}

type WebhookIssue struct {
	Number      int         `json:"number"`
	PullRequest interface{} `json:"pull_request"` // non-nil when the issue is a PR
}

type WebhookPayload struct {
	Action       string          `json:"action"`
	Ref          string          `json:"ref"`
	RefType      string          `json:"ref_type"`
	Sender       WebhookUser     `json:"sender"`
	Repository   WebhookRepo     `json:"repository"`
	PullRequest  *WebhookPR      `json:"pull_request"`
	Comment      *WebhookComment `json:"comment"`
	Issue        *WebhookIssue   `json:"issue"`
	Installation *struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

type issueCommandContext struct {
	token      string
	owner      string
	repo       string
	issue      int
	commenter  string
	commentURL string
	isPR       bool
}

func (c issueCommandContext) comment(body string) {
	if err := safeCreateIssueComment(c.token, c.owner, c.repo, c.issue, body); err != nil {
		log.Printf("Failed to create issue comment on #%d: %v", c.issue, err)
	}
}

func buildFilesSummary(files []PRFile, limit int) string {
	if len(files) == 0 {
		return ""
	}
	if len(files) < limit {
		limit = len(files)
	}

	lines := make([]string, 0, limit)
	for _, f := range files[:limit] {
		lines = append(lines, fmt.Sprintf("%s: %s (+%d/-%d)", f.Status, f.Filename, f.Additions, f.Deletions))
	}
	return strings.Join(lines, "\n")
}

func buildPRContextFromWebhook(pr *WebhookPR, files []PRFile) PRContext {
	return PRContext{
		Title:        pr.Title,
		Author:       pr.User.Login,
		Body:         pr.Body,
		BaseBranch:   pr.Base.Ref,
		HeadBranch:   pr.Head.Ref,
		ChangedFiles: pr.ChangedFiles,
		Additions:    pr.Additions,
		Deletions:    pr.Deletions,
		FilesSummary: buildFilesSummary(files, 30),
	}
}

func resolvePRFiles(token, owner, repo string, pullNumber int) []PRFile {
	files, err := listPRFiles(token, owner, repo, pullNumber)
	if err != nil {
		log.Println("Failed to list PR files:", err)
		return []PRFile{}
	}
	return files
}

func buildPRAnalysisComment(eventType, summaryText, securityReport string, hasVulnerabilities bool) string {
	securityHeader := "✅ No critical security issues detected"
	if hasVulnerabilities {
		securityHeader = "⚠️ **Potential vulnerabilities detected**"
	}

	expandLabel := "Click to expand"
	if hasVulnerabilities {
		expandLabel = "⚠️ Issues found"
	}

	return strings.Join([]string{
		fmt.Sprintf("## 🤖 PR Summary & Security Analysis (%s)", eventType),
		"",
		"### 📝 Summary",
		summaryText,
		"",
		"### 🔒 Security Analysis",
		securityHeader,
		"",
		"<details>",
		fmt.Sprintf("<summary>View security report (%s)</summary>", expandLabel),
		"",
		securityReport,
		"</details>",
	}, "\n")
}

func createSecurityIssueForPR(token, owner, repo string, pullNumber int, prURL, securityReport string) *GitHubIssue {
	issueTitle := fmt.Sprintf("[Security] Vulnerabilities detected in PR #%d", pullNumber)
	issueBody := strings.Join([]string{
		"## Security Vulnerability Report",
		"",
		fmt.Sprintf("Automated security analysis detected potential vulnerabilities in [PR #%d](%s).", pullNumber, prURL),
		"",
		"### Detected Issues",
		"",
		securityReport,
		"",
		"### Recommended Actions",
		"",
		"1. Review the identified vulnerabilities",
		"2. Apply the recommended fixes",
		"3. Re-run security analysis after fixes",
		"",
		"---",
		"*This issue was created automatically by the security bot.*",
	}, "\n")

	issue, err := createGitHubIssue(token, owner, repo, issueTitle, issueBody, []string{"security", "bug", "automated"})
	if err != nil {
		log.Println("Failed to create security issue:", err)
		return nil
	}
	return issue
}

func buildSecurityIssueTelegramMessage(owner, repo string, issueNumber, pullNumber int, issueURL string) string {
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

func fetchPRContextForCommand(token, owner, repo string, prNumber int) (PRContext, error) {
	var prData struct {
		Title        string        `json:"title"`
		Body         string        `json:"body"`
		User         WebhookUser   `json:"user"`
		Base         WebhookBranch `json:"base"`
		Head         WebhookBranch `json:"head"`
		ChangedFiles int           `json:"changed_files"`
		Additions    int           `json:"additions"`
		Deletions    int           `json:"deletions"`
	}

	prURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d", owner, repo, prNumber)
	if err := githubGet(token, prURL, &prData); err != nil {
		return PRContext{}, err
	}

	files, err := listPRFiles(token, owner, repo, prNumber)
	if err != nil {
		return PRContext{}, err
	}

	return PRContext{
		Title:        prData.Title,
		Author:       prData.User.Login,
		Body:         prData.Body,
		BaseBranch:   prData.Base.Ref,
		HeadBranch:   prData.Head.Ref,
		ChangedFiles: prData.ChangedFiles,
		Additions:    prData.Additions,
		Deletions:    prData.Deletions,
		FilesSummary: buildFilesSummary(files, 30),
	}, nil
}

func buildAskPrompt(owner, repo, scope, commenter, commandArgs string) string {
	return strings.Join([]string{
		"You are an AI coding assistant replying inside a GitHub comment thread.",
		"Follow the user's request directly and answer in GitHub-flavored Markdown.",
		"When code is requested, provide concise and runnable examples.",
		"If relevant, include short notes and keep the response practical.",
		"",
		fmt.Sprintf("Repository: %s/%s", owner, repo),
		fmt.Sprintf("Thread type: %s", scope),
		fmt.Sprintf("Requested by: @%s", commenter),
		"",
		"User request:",
		commandArgs,
	}, "\n")
}

// ---------------------------------------------------------------------------
// Core handler: pull request analysis
// ---------------------------------------------------------------------------

func handlePullRequestAnalysis(token string, payload WebhookPayload, eventType string) {
	if strings.EqualFold(payload.Sender.Type, "Bot") {
		log.Println("Skipping bot-triggered PR")
		return
	}

	owner := payload.Repository.Owner.Login
	repo := payload.Repository.Name
	pr := payload.PullRequest
	pullNumber := pr.Number
	prURL := pr.HTMLURL

	log.Printf("Analyzing PR #%d in %s/%s (%s)", pullNumber, owner, repo, eventType)

	files := resolvePRFiles(token, owner, repo, pullNumber)
	prContext := buildPRContextFromWebhook(pr, files)

	// Generate PR summary
	summaryText, err := summarizePullRequestWithQwenCoder(prContext)
	if err != nil {
		log.Println("PR summary failed:", err)
		summaryText = "Could not generate AI summary due to Qwen API error."
	}

	// Perform security analysis
	securityReport := "No security analysis performed."
	hasVulnerabilities := false

	if len(files) > 0 {
		result := analyzeSecurityVulnerabilities(files)
		securityReport = result.Report
		hasVulnerabilities = result.HasVulnerabilities
	}

	// Post summary comment on PR
	prCommentBody := buildPRAnalysisComment(eventType, summaryText, securityReport, hasVulnerabilities)

	if err := safeCreateIssueComment(token, owner, repo, pullNumber, prCommentBody); err != nil {
		log.Println("Failed to post PR comment:", err)
	}

	// Create GitHub issue if vulnerabilities found
	var createdIssue *GitHubIssue
	if hasVulnerabilities {
		createdIssue = createSecurityIssueForPR(token, owner, repo, pullNumber, prURL, securityReport)
	}

	// Send Telegram PR digest
	telegramMessage := buildTelegramPrSummary(owner, repo, pullNumber, prURL, eventType, prContext, summaryText, hasVulnerabilities)
	sendTelegramMessage(telegramMessage)

	// Send Telegram event when a GitHub security issue is created
	if createdIssue != nil {
		sendTelegramMessage(buildSecurityIssueTelegramMessage(owner, repo, createdIssue.Number, pullNumber, createdIssue.HTMLURL))
	}

	vulnSuffix := ""
	if hasVulnerabilities {
		vulnSuffix = " [VULNERABILITIES FOUND]"
	}
	log.Printf("Completed analysis for PR #%d (%s)%s", pullNumber, eventType, vulnSuffix)
}

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

func verifyWebhookSignature(payload []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sig := strings.TrimPrefix(signature, "sha256=")
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(payload)
	expected := fmt.Sprintf("%x", mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}

// ---------------------------------------------------------------------------
// Webhook HTTP handler
// ---------------------------------------------------------------------------

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-GitHub-Delivery")
	name := r.Header.Get("X-GitHub-Event")
	signature := r.Header.Get("X-Hub-Signature-256")

	if id == "" || name == "" || signature == "" {
		http.Error(w, "Missing GitHub webhook headers", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	if !verifyWebhookSignature(body, signature) {
		log.Println("Ignored webhook with invalid signature.")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("Ignored invalid signature"))
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Resolve installation token
	token := ""
	if payload.Installation != nil {
		t, err := getInstallationToken(payload.Installation.ID)
		if err != nil {
			log.Println("Failed to get installation token:", err)
		} else {
			token = t
		}
	}

	// Dispatch event
	go func() {
		switch name {
		case "pull_request":
			if payload.PullRequest == nil {
				return
			}
			switch payload.Action {
			case "opened":
				handlePullRequestAnalysis(token, payload, "opened")
			case "synchronize":
				handlePullRequestAnalysis(token, payload, "synchronize")
			case "reopened":
				handlePullRequestAnalysis(token, payload, "reopened")
			}

		case "create":
			if payload.RefType != "branch" {
				return
			}
			message := strings.Join([]string{
				"🌿 New branch created",
				payload.Repository.FullName,
				fmt.Sprintf("Branch: %s", payload.Ref),
				fmt.Sprintf("By: %s", payload.Sender.Login),
				payload.Repository.HTMLURL,
			}, "\n")
			sendTelegramMessage(message)
			log.Printf("Sent Telegram branch notification for %s.", payload.Ref)

		case "issue_comment":
			if payload.Action != "created" {
				return
			}
			handleIssueCommentCreated(token, payload)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// ---------------------------------------------------------------------------
// Issue comment command handler
// ---------------------------------------------------------------------------

func parseSlashCommand(commentBody string) (string, string) {
	trimmed := strings.TrimSpace(commentBody)
	if !strings.HasPrefix(trimmed, "/") {
		return "", ""
	}

	idx := strings.IndexAny(trimmed, " \t\r\n")
	if idx == -1 {
		return strings.ToLower(trimmed), ""
	}

	command := strings.ToLower(trimmed[:idx])
	args := strings.TrimSpace(trimmed[idx+1:])
	return command, args
}

func buildIssueCommandContext(token string, payload WebhookPayload) issueCommandContext {
	return issueCommandContext{
		token:      token,
		owner:      payload.Repository.Owner.Login,
		repo:       payload.Repository.Name,
		issue:      payload.Issue.Number,
		commenter:  payload.Comment.User.Login,
		commentURL: payload.Comment.HTMLURL,
		isPR:       payload.Issue.PullRequest != nil,
	}
}

func handleAskCommand(ctx issueCommandContext, commandArgs string) {
	if commandArgs == "" {
		ctx.comment("Usage: `/ask <your prompt>`\n\nExample: `/ask write a simple GET handler in Go`")
		return
	}

	ctx.comment("🤖 Processing your /ask request...")

	scope := "issue"
	if ctx.isPR {
		scope = "pull request"
	}

	answer, err := callQwenCoderAPI(buildAskPrompt(ctx.owner, ctx.repo, scope, ctx.commenter, commandArgs))
	if err != nil {
		ctx.comment(fmt.Sprintf("❌ /ask failed: %v", err))
		log.Printf("/ask failed on #%d: %v", ctx.issue, err)
		return
	}

	if strings.TrimSpace(answer) == "" {
		answer = "I could not generate a response for that prompt."
	}

	response := strings.Join([]string{
		"## 🤖 AI Response (/ask)",
		"",
		answer,
	}, "\n")
	ctx.comment(response)
	log.Printf("/ask completed for @%s on #%d", ctx.commenter, ctx.issue)
}

func handleSecurityCommand(ctx issueCommandContext) {
	ctx.comment("🔍 Running security scan...")

	var files []PRFile
	if ctx.isPR {
		var err error
		files, err = listPRFiles(ctx.token, ctx.owner, ctx.repo, ctx.issue)
		if err != nil {
			log.Println("Failed to list PR files for security scan:", err)
		}
	}

	if len(files) == 0 {
		ctx.comment("No files to analyze. This command works best on pull requests.")
		return
	}

	result := analyzeSecurityVulnerabilities(files)
	vulnHeader := "✅ **No issues found**"
	if result.HasVulnerabilities {
		vulnHeader = "⚠️ **Vulnerabilities detected**"
	}
	resultBody := strings.Join([]string{
		"## 🔒 Security Scan Results",
		"",
		vulnHeader,
		"",
		result.Report,
	}, "\n")
	ctx.comment(resultBody)

	if result.HasVulnerabilities {
		sendTelegramMessage(fmt.Sprintf("⚠️ Security issues found in %s/%s#%d\nRequested by @%s", ctx.owner, ctx.repo, ctx.issue, ctx.commenter))
	}

	log.Printf("Security scan requested by @%s on #%d", ctx.commenter, ctx.issue)
}

func handleSummarizeCommand(ctx issueCommandContext) {
	if !ctx.isPR {
		ctx.comment("This command only works on pull requests.")
		return
	}

	prContext, err := fetchPRContextForCommand(ctx.token, ctx.owner, ctx.repo, ctx.issue)
	if err != nil {
		ctx.comment(fmt.Sprintf("❌ Summary failed: %v", err))
		return
	}

	summary, err := summarizePullRequestWithQwenCoder(prContext)
	if err != nil {
		ctx.comment(fmt.Sprintf("❌ Summary failed: %v", err))
		return
	}

	ctx.comment("## 📝 PR Summary & Recommendations (on-demand)\n\n" + summary)
	log.Printf("Summary requested by @%s on PR #%d", ctx.commenter, ctx.issue)
}

func handleCodeCommand(ctx issueCommandContext, commandArgs string) {
	echoMessage := "Echo: (no text provided after /code)"
	if commandArgs != "" {
		echoMessage = "Echo: " + commandArgs
	}
	ctx.comment(echoMessage)
	log.Println("Responded to /code command.")
}

func handleCloseIssueCommand(ctx issueCommandContext, commandArgs string) {
	if err := closeGitHubIssue(ctx.token, ctx.owner, ctx.repo, ctx.issue); err != nil {
		log.Println("Failed to close issue:", err)
		return
	}

	closeMessage := fmt.Sprintf("Issue closed by command from @%s.", ctx.commenter)
	if commandArgs != "" {
		closeMessage = fmt.Sprintf("Issue closed by command from @%s. Reason: %s", ctx.commenter, commandArgs)
	}
	ctx.comment(closeMessage)
	log.Println("Closed issue from /closeissue command.")
}

func handleSendPicCommand(ctx issueCommandContext, commandArgs string) {
	imageURL := commandArgs
	if imageURL == "" {
		imageURL = "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png"
	}
	ctx.comment(fmt.Sprintf("Here is your picture:\n\n![image](%s)", imageURL))
	log.Println("Responded to /sendpic command.")
}

func handleMarkdownCommand(ctx issueCommandContext) {
	markdownMessage := strings.Join([]string{
		"## Markdown Response",
		"",
		"This is a sample markdown message:",
		"",
		"- Item 1",
		"- Item 2",
		"",
		"**Bold text** and _italic text_",
		"",
		"```js",
		`console.log("Hello from markdown");`,
		"```",
	}, "\n")
	ctx.comment(markdownMessage)
	log.Println("Responded to /markdown command.")
}

func handleSendAndExitCommand(ctx issueCommandContext, commandArgs string) {
	sendMsg := commandArgs
	if sendMsg == "" {
		sendMsg = "Message sent via /sendandexit."
	}
	replyBody := fmt.Sprintf("@%s %s\n\nIn reply to your command comment: %s", ctx.commenter, sendMsg, ctx.commentURL)
	ctx.comment(replyBody)
	log.Println("Responded to /sendandexit command.")
}

func handleUnknownCommand(ctx issueCommandContext, command string) {
	unknownMsg := fmt.Sprintf(
		"❓ Unknown command: %s\n\nAvailable commands: `/ask`, `/security`, `/scan`, `/summarize`, `/code`, `/closeissue`, `/sendpic`, `/markdown`, `/sendandexit`",
		command,
	)
	ctx.comment(unknownMsg)
	log.Println("Responded with unknown command message.")
}

func handleIssueCommentCreated(token string, payload WebhookPayload) {
	if strings.EqualFold(payload.Sender.Type, "Bot") {
		return
	}
	if payload.Comment == nil || payload.Issue == nil {
		return
	}

	commentBody := strings.TrimSpace(payload.Comment.Body)
	if !strings.HasPrefix(commentBody, "/") {
		return
	}

	command, commandArgs := parseSlashCommand(commentBody)
	if command == "" {
		return
	}
	ctx := buildIssueCommandContext(token, payload)

	switch command {
	case "/ask":
		handleAskCommand(ctx, commandArgs)

	case "/security", "/scan":
		handleSecurityCommand(ctx)

	case "/summarize":
		handleSummarizeCommand(ctx)

	case "/code":
		handleCodeCommand(ctx, commandArgs)

	case "/closeissue":
		handleCloseIssueCommand(ctx, commandArgs)

	case "/sendpic":
		handleSendPicCommand(ctx, commandArgs)

	case "/markdown":
		handleMarkdownCommand(ctx)

	case "/sendandexit":
		handleSendAndExitCommand(ctx, commandArgs)

	default:
		handleUnknownCommand(ctx, command)
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

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

func main() {
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
	fmt.Sscanf(appIDStr, "%d", &appID)

	webhookSecret = os.Getenv("WEBHOOK_SECRET")
	rawKey := os.Getenv("PRIVATE_KEY")
	privateKeyPEM = normalizePrivateKey(rawKey)
	qwenBearerToken = os.Getenv("QWEN_BEARER_TOKEN")
	telegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	telegramChatId = os.Getenv("TELEGRAM_CHAT_ID")

	if appID == 0 || webhookSecret == "" || privateKeyPEM == "" {
		log.Fatal("Missing APP_ID, WEBHOOK_SECRET, or PRIVATE_KEY in environment")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("🤖 GitHub Security Bot is running with Qwen Coder AI"))
	})

	// Webhook endpoint
	mux.HandleFunc("/api/github/webhooks", webhookHandler)

	qwenStatus := "NOT configured"
	if qwenBearerToken != "" || hardcodedQwenBearerToken != "" {
		qwenStatus = "configured"
	}
	telegramStatus := "NOT configured"
	if telegramBotToken != "" && telegramChatId != "" {
		telegramStatus = "configured"
	}

	log.Printf("Server is running on port %s", port)
	log.Printf("Qwen API: %s", qwenStatus)
	log.Printf("Telegram: %s", telegramStatus)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
