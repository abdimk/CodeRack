package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/abdimk/coderack/config"
)

// ---------------------------------------------------------------------------
// GitHub REST helpers
// ---------------------------------------------------------------------------

type PRFile struct {
	Filename  string `json:"filename"`
	Status    string `json:"status"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Patch     string `json:"patch"`
}

type Installation struct {
	ID int64 `json:"id"`
}

func GetInstallationToken(installationID int64) (string, error) {
	jwtToken, err := config.GenerateJWT()
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


// GithubGet performs a GET request authenticated with the installation token.
func GithubGet(token, url string, out interface{}) error {
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

// GithubPost performs a POST request authenticated with the installation token.
func GithubPost(token, url string, body interface{}, out interface{}) (int, error) {
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

// GithubPatch performs a PATCH request (for updating issues).
func GithubPatch(token, url string, body interface{}, out interface{}) (int, error) {
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

func ListPRFiles(token, owner, repo string, pullNumber int) ([]PRFile, error) {
	var all []PRFile
	page := 1
	for {
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d/files?per_page=100&page=%d", owner, repo, pullNumber, page)
		var files []PRFile
		if err := GithubGet(token, url, &files); err != nil {
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

func IsIntegrationPermissionError(statusCode int, body string) bool {
	return statusCode == 403 && strings.Contains(body, "Resource not accessible by integration")
}

func SafeCreateIssueComment(token, owner, repo string, issueNumber int, body string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d/comments", owner, repo, issueNumber)
	payload := map[string]string{"body": body}

	var result map[string]interface{}
	status, err := GithubPost(token, url, payload, &result)
	if err != nil {
		return err
	}
	if status == 403 {
		resp403Body, _ := json.Marshal(result)
		if IsIntegrationPermissionError(status, string(resp403Body)) {
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

func CreateGitHubIssue(token, owner, repo string, title, body string, labels []string) (*GitHubIssue, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", owner, repo)
	payload := map[string]interface{}{
		"title":  title,
		"body":   body,
		"labels": labels,
	}
	var issue GitHubIssue
	status, err := GithubPost(token, url, payload, &issue)
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

func CloseGitHubIssue(token, owner, repo string, issueNumber int) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d", owner, repo, issueNumber)
	payload := map[string]string{"state": "closed"}
	_, err := GithubPatch(token, url, payload, nil)
	return err
}
