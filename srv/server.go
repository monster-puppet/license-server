package srv

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"srv.exe.dev/db"
	"srv.exe.dev/db/dbgen"
)

type Server struct {
	DB             *sql.DB
	LibFolder      string
	LatestFile     string
	GoogleClientID string
	GoogleSecret   string
	AdminEmails    []string
	BaseURL        string
	TemplatesDir   string
}

func New(dbPath string) (*Server, error) {
	libFolder := "/home/exedev/hubv2/lib"
	if err := os.MkdirAll(libFolder, 0755); err != nil {
		return nil, fmt.Errorf("create lib folder: %w", err)
	}

	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	adminEmail := os.Getenv("ADMIN_EMAIL")
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "https://license-server.exe.xyz:8000"
	}

	_, thisFile, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(thisFile)

	srv := &Server{
		LibFolder:      libFolder,
		LatestFile:     "mk.zip",
		GoogleClientID: googleClientID,
		GoogleSecret:   googleSecret,
		AdminEmails:    []string{adminEmail},
		BaseURL:        baseURL,
		TemplatesDir:   filepath.Join(baseDir, "templates"),
	}

	if err := srv.setUpDatabase(dbPath); err != nil {
		return nil, err
	}

	// Migrate tokens from env vars to DB if needed
	if err := srv.migrateTokensFromEnv(); err != nil {
		slog.Warn("failed to migrate tokens from env", "error", err)
	}

	return srv, nil
}

func (s *Server) setUpDatabase(dbPath string) error {
	wdb, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open db: %w", err)
	}
	s.DB = wdb
	if err := db.RunMigrations(wdb); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}
	return nil
}

func (s *Server) migrateTokensFromEnv() error {
	q := dbgen.New(s.DB)
	ctx := context.Background()

	// Check if tokens already exist
	tokens, err := q.GetAllTokens(ctx)
	if err != nil {
		return err
	}
	if len(tokens) > 0 {
		return nil // Already migrated
	}

	// Migrate from env vars
	if t := os.Getenv("UPLOAD_TOKEN"); t != "" {
		_, err := q.CreateToken(ctx, dbgen.CreateTokenParams{
			Name:      "upload",
			Token:     t,
			TokenType: "upload",
		})
		if err != nil {
			slog.Warn("failed to migrate upload token", "error", err)
		}
	}
	if t := os.Getenv("DOWNLOAD_TOKEN_PLAYBYPAY"); t != "" {
		_, err := q.CreateToken(ctx, dbgen.CreateTokenParams{
			Name:      "playbypay",
			Token:     t,
			TokenType: "download",
		})
		if err != nil {
			slog.Warn("failed to migrate playbypay token", "error", err)
		}
	}
	if t := os.Getenv("DOWNLOAD_TOKEN_ADMIN"); t != "" {
		_, err := q.CreateToken(ctx, dbgen.CreateTokenParams{
			Name:      "admin",
			Token:     t,
			TokenType: "download",
		})
		if err != nil {
			slog.Warn("failed to migrate admin token", "error", err)
		}
	}

	slog.Info("migrated tokens from environment variables to database")
	return nil
}

func (s *Server) getDownloadTokens() []string {
	q := dbgen.New(s.DB)
	tokens, err := q.GetDownloadTokens(context.Background())
	if err != nil {
		slog.Warn("failed to get download tokens", "error", err)
		return nil
	}
	return tokens
}

func (s *Server) getUploadToken() string {
	q := dbgen.New(s.DB)
	token, err := q.GetUploadToken(context.Background())
	if err != nil {
		slog.Warn("failed to get upload token", "error", err)
		return ""
	}
	return token
}

func (s *Server) HandleRoot(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "The requested resource could not be found", http.StatusNotFound)
}

func (s *Server) HandleDownloadLatest(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if !s.isValidDownloadToken(token) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Invalid token"}`))
		return
	}

	filePath := filepath.Join(s.LibFolder, s.LatestFile)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "File not found"}`))
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", s.LatestFile))
	http.ServeFile(w, r, filePath)
}

func (s *Server) HandleUploadLatest(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token != s.getUploadToken() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Invalid token"}`))
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Failed to parse form"}`))
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "No file provided"}`))
		return
	}
	defer file.Close()

	filePath := filepath.Join(s.LibFolder, s.LatestFile)
	dst, err := os.Create(filePath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`{"error": "Failed to create file", "details": "%s"}`, err.Error())))
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`{"error": "Failed to save file", "details": "%s"}`, err.Error())))
		return
	}

	slog.Info("Uploaded new file", "path", filePath)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"message": "File uploaded successfully", "filename": "%s"}`, s.LatestFile)))
}

func (s *Server) isValidDownloadToken(token string) bool {
	for _, t := range s.getDownloadTokens() {
		if token == t {
			return true
		}
	}
	return false
}

// OAuth and Admin handlers

func (s *Server) HandleAdminLogin(w http.ResponseWriter, r *http.Request) {
	state := generateRandomString(32)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	authURL := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=email&state=%s",
		url.QueryEscape(s.GoogleClientID),
		url.QueryEscape(s.BaseURL+"/admin/callback"),
		url.QueryEscape(state),
	)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (s *Server) HandleAdminCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {s.GoogleClientID},
		"client_secret": {s.GoogleSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {s.BaseURL + "/admin/callback"},
	})
	if err != nil {
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}
	defer tokenResp.Body.Close()

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
	}

	// Get user info
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	userResp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer userResp.Body.Close()

	var userData struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&userData); err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	// Check if email is allowed
	allowed := false
	for _, e := range s.AdminEmails {
		if e == userData.Email {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Create session
	sessionID := generateRandomString(64)
	q := dbgen.New(s.DB)
	err = q.CreateSession(r.Context(), dbgen.CreateSessionParams{
		ID:        sessionID,
		Email:     userData.Email,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})

	http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
}

func (s *Server) HandleAdminLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		q := dbgen.New(s.DB)
		q.DeleteSession(r.Context(), cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/admin/login", http.StatusTemporaryRedirect)
}

func (s *Server) getSessionEmail(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}

	q := dbgen.New(s.DB)
	session, err := q.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return ""
	}
	return session.Email
}

func (s *Server) HandleAdmin(w http.ResponseWriter, r *http.Request) {
	email := s.getSessionEmail(r)
	if email == "" {
		http.Redirect(w, r, "/admin/login", http.StatusTemporaryRedirect)
		return
	}

	q := dbgen.New(s.DB)
	tokens, err := q.GetAllTokens(r.Context())
	if err != nil {
		http.Error(w, "Failed to get tokens", http.StatusInternalServerError)
		return
	}

	data := struct {
		Email  string
		Tokens []dbgen.Token
	}{
		Email:  email,
		Tokens: tokens,
	}

	tmpl, err := template.ParseFiles(filepath.Join(s.TemplatesDir, "admin.html"))
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func (s *Server) HandleAdminUpdateToken(w http.ResponseWriter, r *http.Request) {
	email := s.getSessionEmail(r)
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	idStr := r.FormValue("id")
	newToken := r.FormValue("token")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	q := dbgen.New(s.DB)
	err = q.UpdateToken(r.Context(), dbgen.UpdateTokenParams{
		ID:    id,
		Token: newToken,
	})
	if err != nil {
		http.Error(w, "Failed to update token", http.StatusInternalServerError)
		return
	}

	slog.Info("Token updated", "id", id, "by", email)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func generateToken() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 57)
	rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

func (s *Server) HandleAdminCreateToken(w http.ResponseWriter, r *http.Request) {
	email := s.getSessionEmail(r)
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "Missing name", http.StatusBadRequest)
		return
	}

	tokenValue := generateToken()

	q := dbgen.New(s.DB)
	_, err := q.CreateToken(r.Context(), dbgen.CreateTokenParams{
		Name:      name,
		Token:     tokenValue,
		TokenType: "download",
	})
	if err != nil {
		http.Error(w, "Failed to create token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("Token created", "name", name, "by", email)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) HandleAdminDeleteToken(w http.ResponseWriter, r *http.Request) {
	email := s.getSessionEmail(r)
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	idStr := r.FormValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	q := dbgen.New(s.DB)

	// Check if it's an upload token - prevent deletion
	tokens, _ := q.GetAllTokens(r.Context())
	for _, t := range tokens {
		if t.ID == id && t.TokenType == "upload" {
			http.Error(w, "Cannot delete upload token", http.StatusForbidden)
			return
		}
	}

	err = q.DeleteToken(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to delete token", http.StatusInternalServerError)
		return
	}

	slog.Info("Token deleted", "id", id, "by", email)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func generateRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:n]
}

func (s *Server) Serve(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.HandleRoot)
	mux.HandleFunc("GET /download/latest", s.HandleDownloadLatest)
	mux.HandleFunc("POST /upload/latest", s.HandleUploadLatest)

	// Admin routes
	mux.HandleFunc("GET /admin", s.HandleAdmin)
	mux.HandleFunc("GET /admin/login", s.HandleAdminLogin)
	mux.HandleFunc("GET /admin/callback", s.HandleAdminCallback)
	mux.HandleFunc("GET /admin/logout", s.HandleAdminLogout)
	mux.HandleFunc("POST /admin/token/update", s.HandleAdminUpdateToken)
	mux.HandleFunc("POST /admin/token/create", s.HandleAdminCreateToken)
	mux.HandleFunc("POST /admin/token/delete", s.HandleAdminDeleteToken)

	slog.Info("starting server", "addr", addr)
	return http.ListenAndServe(addr, mux)
}
