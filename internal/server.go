package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/abdimk/coderack/utils"
)

func WebhookHandler(w http.ResponseWriter, r *http.Request) {
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

	if !VerifyWebhookSignature(body, signature) {
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
		t, err := utils.GetInstallationToken(payload.Installation.ID)
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
				HandlePullRequestAnalysis(token, payload, "opened")
			case "synchronize":
				HandlePullRequestAnalysis(token, payload, "synchronize")
			case "reopened":
				HandlePullRequestAnalysis(token, payload, "reopened")
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
			utils.SendTelegramMessage(message)
			log.Printf("Sent Telegram branch notification for %s.", payload.Ref)

		case "issue_comment":
			if payload.Action != "created" {
				return
			}
			HandleIssueCommentCreated(token, payload)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func StartServer(port string) error {
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
	mux.HandleFunc("/api/github/webhooks", WebhookHandler)

	log.Printf("Server is running on port %s", port)
	return http.ListenAndServe(":"+port, mux)
}
