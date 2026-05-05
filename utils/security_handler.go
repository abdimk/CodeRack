package utils

import (
	"fmt"
	"log"
	"strings"

	"github.com/abdimk/coderack/config"
)

// ---------------------------------------------------------------------------
// Security analysis
// ---------------------------------------------------------------------------

type SecurityResult struct {
	HasVulnerabilities bool
	Report             string
}

func AnalyzeSecurityVulnerabilities(files []PRFile) SecurityResult {
	if config.QwenBearerToken == "" {
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

	analysis, err := CallQwenCoderAPI(prompt)
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
