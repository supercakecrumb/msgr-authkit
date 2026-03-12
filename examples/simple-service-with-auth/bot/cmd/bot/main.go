package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	tele "gopkg.in/telebot.v3"
)

type loginLinkResponse struct {
	LoginURL string `json:"login_url"`
	Error    string `json:"error"`
}

func main() {
	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	if token == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN is required")
	}
	webBaseURL := strings.TrimRight(env("WEB_INTERNAL_BASE_URL", "http://web:8080"), "/")
	internalToken := env("INTERNAL_API_TOKEN", "dev-internal-token")
	timeout := time.Duration(envInt("POLL_TIMEOUT_SECONDS", 25)) * time.Second

	bot, err := tele.NewBot(tele.Settings{
		Token:  token,
		Poller: &tele.LongPoller{Timeout: timeout},
	})
	if err != nil {
		log.Fatal(err)
	}

	handler := func(c tele.Context) error {
		if c.Sender() == nil {
			return c.Send("No Telegram user in update")
		}
		loginURL, err := requestLoginLink(webBaseURL, internalToken, c.Sender())
		if err != nil {
			return c.Send("Could not create login link. Try again in a moment.")
		}
		if !canUseInlineURLButton(loginURL) {
			return c.Send("Open this link to login:\n" + loginURL)
		}
		menu := &tele.ReplyMarkup{}
		open := menu.URL("Open Login", loginURL)
		menu.Inline(menu.Row(open))
		return c.Send("Tap the button to login.", menu)
	}

	bot.Handle("/start", handler)
	bot.Handle("/login", handler)
	log.Println("bot started")
	bot.Start()
}

func requestLoginLink(webBaseURL, internalToken string, user *tele.User) (string, error) {
	body, _ := json.Marshal(map[string]any{"user": user})
	req, err := http.NewRequest(http.MethodPost, webBaseURL+"/internal/telegram/login-link", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+internalToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)
	var out loginLinkResponse
	if err := json.Unmarshal(responseBody, &out); err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		if out.Error == "" {
			out.Error = string(responseBody)
		}
		return "", fmt.Errorf("web returned %d: %s", resp.StatusCode, out.Error)
	}
	if strings.TrimSpace(out.LoginURL) == "" {
		return "", fmt.Errorf("empty login_url")
	}
	return out.LoginURL, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func canUseInlineURLButton(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	if parsed.Scheme != "https" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host != "" && host != "localhost" && host != "127.0.0.1"
}
