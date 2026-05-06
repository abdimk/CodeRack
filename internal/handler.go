package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log"
	"strings"

	"github.com/abdimk/coderack/config"
	"github.com/abdimk/coderack/utils"
)

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

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

func VerifyWebhookSignature(payload []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sig := strings.TrimPrefix(signature, "sha256=")
	mac := hmac.New(sha256.New, []byte(config.WebhookSecret))
	mac.Write(payload)
	expected := fmt.Sprintf("%x", mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}

// ---------------------------------------------------------------------------
// Core handler: pull request analysis
// ---------------------------------------------------------------------------

func HandlePullRequestAnalysis(token string, payload WebhookPayload, eventType string) {
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

	files, err := utils.ListPRFiles(token, owner, repo, pullNumber)
	if err != nil {
		log.Println("Failed to list PR files:", err)
		files = []utils.PRFile{}
	}

	prContext := buildPRContextFromWebhook(pr, files)

	// Generate PR summary
	summaryText, err := utils.SummarizePullRequestWithQwenCoder(prContext)
	if err != nil {
		log.Println("PR summary failed:", err)
		summaryText = "Could not generate AI summary due to Qwen API error."
	}

	// Perform security analysis
	securityReport := "No security analysis performed."
	hasVulnerabilities := false

	if len(files) > 0 {
		result := utils.AnalyzeSecurityVulnerabilities(files)
		securityReport = result.Report
		hasVulnerabilities = result.HasVulnerabilities
	}

	// Post summary comment on PR
	prCommentBody := buildPRAnalysisComment(eventType, summaryText, securityReport, hasVulnerabilities)

	if err := utils.SafeCreateIssueComment(token, owner, repo, pullNumber, prCommentBody); err != nil {
		log.Println("Failed to post PR comment:", err)
	}

	// Create GitHub issue if vulnerabilities found
	var createdIssue *utils.GitHubIssue
	if hasVulnerabilities {
		createdIssue = createSecurityIssueForPR(token, owner, repo, pullNumber, prURL, securityReport)
	}

	// Send Telegram PR digest
	telegramMessage := utils.BuildTelegramPrSummary(owner, repo, pullNumber, prURL, eventType, utils.PRContext(prContext), summaryText, hasVulnerabilities)
	utils.SendTelegramMessage(telegramMessage)

	// Send Telegram event when a GitHub security issue is created
	if createdIssue != nil {
		utils.SendTelegramMessage(utils.BuildSecurityIssueTelegramMessage(owner, repo, createdIssue.Number, pullNumber, createdIssue.HTMLURL))
	}

	vulnSuffix := ""
	if hasVulnerabilities {
		vulnSuffix = " [VULNERABILITIES FOUND]"
	}
	log.Printf("Completed analysis for PR #%d (%s)%s", pullNumber, eventType, vulnSuffix)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildFilesSummary(files []utils.PRFile, limit int) string {
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

func buildPRContextFromWebhook(pr *WebhookPR, files []utils.PRFile) utils.PRContext {
	return utils.PRContext{
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

func createSecurityIssueForPR(token, owner, repo string, pullNumber int, prURL, securityReport string) *utils.GitHubIssue {
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

	issue, err := utils.CreateGitHubIssue(token, owner, repo, issueTitle, issueBody, []string{"security", "bug", "automated"})
	if err != nil {
		log.Println("Failed to create security issue:", err)
		return nil
	}
	return issue
}

// ---------------------------------------------------------------------------
// Handle newly opened issues
// ---------------------------------------------------------------------------

func HandleIssueOpened(token string, payload WebhookPayload) {
	if strings.EqualFold(payload.Sender.Type, "Bot") {
		return
	}
	if payload.Issue == nil {
		return
	}

	owner := payload.Repository.Owner.Login
	repo := payload.Repository.Name
	issueNumber := payload.Issue.Number
	opener := payload.Sender.Login

	// Post a friendly acknowledgement comment (no-op if app lacks permission)
	welcome := fmt.Sprintf("Thanks @%s for opening this issue — the security bot will review it shortly.", opener)
	if err := utils.SafeCreateIssueComment(token, owner, repo, issueNumber, welcome); err != nil {
		log.Printf("Failed to post welcome comment on issue #%d: %v", issueNumber, err)
	}

	// Send a Telegram notification for visibility
	telegramMsg := fmt.Sprintf("🆕 New issue in %s/%s: #%d opened by @%s\n%s", owner, repo, issueNumber, opener, payload.Repository.HTMLURL)
	utils.SendTelegramMessage(telegramMsg)

	log.Printf("Handled opened issue #%d in %s/%s", issueNumber, owner, repo)
}

// Issue comment command handler
// ---------------------------------------------------------------------------

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
	if err := utils.SafeCreateIssueComment(c.token, c.owner, c.repo, c.issue, body); err != nil {
		log.Printf("Failed to create issue comment on #%d: %v", c.issue, err)
	}
}

func ParseSlashCommand(commentBody string) (string, string) {
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

func HandleIssueCommentCreated(token string, payload WebhookPayload) {
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

	command, commandArgs := ParseSlashCommand(commentBody)
	if command == "" {
		return
	}
	ctx := issueCommandContext{
		token:      token,
		owner:      payload.Repository.Owner.Login,
		repo:       payload.Repository.Name,
		issue:      payload.Issue.Number,
		commenter:  payload.Comment.User.Login,
		commentURL: payload.Comment.HTMLURL,
		isPR:       payload.Issue.PullRequest != nil,
	}

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

	prompt := strings.Join([]string{
		"You are an AI coding assistant replying inside a GitHub comment thread.",
		"Follow the user's request directly and answer in GitHub-flavored Markdown.",
		"When code is requested, provide concise and runnable examples.",
		"If relevant, include short notes and keep the response practical.",
		"",
		fmt.Sprintf("Repository: %s/%s", ctx.owner, ctx.repo),
		fmt.Sprintf("Thread type: %s", scope),
		fmt.Sprintf("Requested by: @%s", ctx.commenter),
		"",
		"User request:",
		commandArgs,
	}, "\n")

	answer, err := utils.CallQwenCoderAPI(prompt)
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

	var files []utils.PRFile
	if ctx.isPR {
		var err error
		files, err = utils.ListPRFiles(ctx.token, ctx.owner, ctx.repo, ctx.issue)
		if err != nil {
			log.Println("Failed to list PR files for security scan:", err)
		}
	}

	if len(files) == 0 {
		ctx.comment("No files to analyze. This command works best on pull requests.")
		return
	}

	result := utils.AnalyzeSecurityVulnerabilities(files)
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
		utils.SendTelegramMessage(fmt.Sprintf("⚠️ Security issues found in %s/%s#%d\nRequested by @%s", ctx.owner, ctx.repo, ctx.issue, ctx.commenter))
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

	summary, err := utils.SummarizePullRequestWithQwenCoder(prContext)
	if err != nil {
		ctx.comment(fmt.Sprintf("❌ Summary failed: %v", err))
		return
	}

	ctx.comment("## 📝 PR Summary & Recommendations (on-demand)\n\n" + summary)
	log.Printf("Summary requested by @%s on PR #%d", ctx.commenter, ctx.issue)
}

func fetchPRContextForCommand(token, owner, repo string, prNumber int) (utils.PRContext, error) {
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
	if err := utils.GithubGet(token, prURL, &prData); err != nil {
		return utils.PRContext{}, err
	}

	files, err := utils.ListPRFiles(token, owner, repo, prNumber)
	if err != nil {
		return utils.PRContext{}, err
	}

	return utils.PRContext{
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

func handleCodeCommand(ctx issueCommandContext, commandArgs string) {
	echoMessage := "Echo: (no text provided after /code)"
	if commandArgs != "" {
		echoMessage = "Echo: " + commandArgs
	}
	ctx.comment(echoMessage)
	log.Println("Responded to /code command.")
}

func handleCloseIssueCommand(ctx issueCommandContext, commandArgs string) {
	if err := utils.CloseGitHubIssue(ctx.token, ctx.owner, ctx.repo, ctx.issue); err != nil {
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
