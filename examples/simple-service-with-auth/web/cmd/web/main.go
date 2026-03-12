package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	authkit "github.com/supercakecrumb/msgr-authkit"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type TelegramProfile struct {
	SubjectID       string `gorm:"primaryKey"`
	MessengerUserID string `gorm:"uniqueIndex"`
	Username        string
	FirstName       string
	LastName        string
	LanguageCode    string
	RawJSON         string `gorm:"type:text"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type loginLinkRequest struct {
	User map[string]any `json:"user"`
}

func main() {
	appAddr := env("APP_ADDR", ":8080")
	dsn := env("DATABASE_URL", "postgres://postgres:postgres@postgres:5432/auth_example?sslmode=disable")
	publicBaseURL := strings.TrimRight(env("PUBLIC_BASE_URL", "http://localhost:8080"), "/")
	internalToken := env("INTERNAL_API_TOKEN", "dev-internal-token")
	botUsername := strings.TrimSpace(os.Getenv("BOT_USERNAME"))

	db, err := openDBWithRetry(dsn, 30*time.Second)
	must(err)
	must(db.AutoMigrate(&TelegramProfile{}))

	issuer, err := authkit.NewInMemorySessionIssuer(2 * time.Minute)
	must(err)
	authService, err := authkit.NewAuthService(
		authkit.NewInMemoryIntentStore(),
		authkit.NewInMemoryLinkStore(),
		issuer,
		authkit.WithSignedQueryLoginLinks(publicBaseURL+"/auth/redeem", []byte(internalToken), "auth_token"),
		authkit.WithMissingIdentityLinkMode(authkit.MissingIdentityLinkAutoProvision),
		authkit.WithLinkProvisioner(authkit.LinkProvisionerFunc(func(_ context.Context, identity authkit.Identity) (authkit.AccountLink, error) {
			return authkit.AccountLink{AppUserID: "tg:" + identity.MessengerUserID, Identity: identity, LinkedAt: time.Now().UTC()}, nil
		})),
	)
	must(err)

	http.HandleFunc("/internal/telegram/login-link", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+internalToken {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		var req loginLinkRequest
		if err := json.Unmarshal(body, &req); err != nil || len(req.User) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user payload is required"})
			return
		}

		id := asString(req.User["id"])
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user.id is required"})
			return
		}

		raw, _ := json.Marshal(req.User)
		profile := TelegramProfile{
			SubjectID:       "tg:" + id,
			MessengerUserID: id,
			Username:        asString(req.User["username"]),
			FirstName:       asString(req.User["first_name"]),
			LastName:        asString(req.User["last_name"]),
			LanguageCode:    asString(req.User["language_code"]),
			RawJSON:         string(raw),
		}
		if err := db.Where("subject_id = ?", profile.SubjectID).Assign(profile).FirstOrCreate(&TelegramProfile{}).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		out, err := authService.CreateLoginLink(r.Context(), authkit.CreateLoginLinkInput{
			Messenger: authkit.NewMessenger("telegram"),
			Audience:  "web",
			Identity: &authkit.Identity{
				Messenger:       authkit.NewMessenger("telegram"),
				MessengerUserID: id,
				Username:        profile.Username,
				Name:            profile.FirstName,
				Surname:         profile.LastName,
				Attributes:      toStringMap(req.User),
			},
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"login_url": out.LoginURL})
	})

	http.HandleFunc("/auth/redeem", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(r.URL.Query().Get("auth_token"))
		session, err := authService.RedeemLoginLink(r.Context(), authkit.RedeemLoginLinkInput{LinkToken: token})
		if err != nil {
			http.Error(w, "login failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		var profile TelegramProfile
		if err := db.Where("subject_id = ?", session.SubjectID).First(&profile).Error; err != nil {
			http.Error(w, "profile not found", http.StatusUnauthorized)
			return
		}

		data := pageData{
			LoggedIn:  true,
			SubjectID: session.SubjectID,
			Username:  profile.Username,
			FirstName: profile.FirstName,
			LastName:  profile.LastName,
			BotURL:    botLink(botUsername),
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, []byte(profile.RawJSON), "", "  "); err == nil {
			data.PrettyJSON = pretty.String()
		} else {
			data.PrettyJSON = profile.RawJSON
		}
		renderPage(w, data)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		renderPage(w, pageData{BotURL: botLink(botUsername)})
	})

	log.Printf("web listening on %s", appAddr)
	must(http.ListenAndServe(appAddr, nil))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func botLink(username string) string {
	if username == "" {
		return ""
	}
	return "https://t.me/" + strings.TrimPrefix(username, "@") + "?start=login"
}

func toStringMap(m map[string]any) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = asString(v)
	}
	return out
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func must(err error) {
	if err == nil {
		return
	}
	panic(fmt.Sprintf("fatal: %v", err))
}

func openDBWithRetry(dsn string, wait time.Duration) (*gorm.DB, error) {
	deadline := time.Now().Add(wait)
	var lastErr error
	for time.Now().Before(deadline) {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err == nil {
			sqlDB, pingErr := db.DB()
			if pingErr == nil {
				if err = sqlDB.Ping(); err == nil {
					return db, nil
				}
			} else {
				err = pingErr
			}
		}
		lastErr = err
		time.Sleep(1 * time.Second)
	}
	return nil, fmt.Errorf("database not ready after %s: %w", wait, lastErr)
}
