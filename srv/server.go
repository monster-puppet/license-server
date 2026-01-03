package srv

import (
	"archive/zip"
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
	"strings"
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
	s.HandleAdmin(w, r)
}

// validMayaVersions defines the supported Maya versions
var validMayaVersions = map[string]bool{
	"2023": true,
	"2024": true,
	"2025": true,
	"2026": true,
}

func (s *Server) HandleDownloadLatest(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if !s.isValidDownloadToken(token) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Invalid token"}`))
		return
	}

	// Get Maya version from query param or header
	mayaVersion := r.URL.Query().Get("maya_version")
	if mayaVersion == "" {
		mayaVersion = r.Header.Get("X-Maya-Version")
	}

	var filePath string
	var fileName string

	if mayaVersion != "" && validMayaVersions[mayaVersion] {
		// Version-specific file
		fileName = fmt.Sprintf("mk_%s.zip", mayaVersion)
		filePath = filepath.Join(s.LibFolder, fileName)
		
		// If version-specific file doesn't exist, fall back to generic
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			slog.Warn("Version-specific file not found, falling back to generic", "maya_version", mayaVersion)
			fileName = s.LatestFile
			filePath = filepath.Join(s.LibFolder, s.LatestFile)
		}
	} else {
		// Generic file (backward compatibility)
		fileName = s.LatestFile
		filePath = filepath.Join(s.LibFolder, s.LatestFile)
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "File not found"}`))
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
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

	// Get Maya version from query param or header
	mayaVersion := r.URL.Query().Get("maya_version")
	if mayaVersion == "" {
		mayaVersion = r.Header.Get("X-Maya-Version")
	}

	// Determine filename based on Maya version
	var fileName string
	var mayaVersionPtr *string
	if mayaVersion != "" && validMayaVersions[mayaVersion] {
		fileName = fmt.Sprintf("mk_%s.zip", mayaVersion)
		mayaVersionPtr = &mayaVersion
	} else {
		// Generic upload (backward compatibility)
		fileName = s.LatestFile
		mayaVersionPtr = nil
	}

	filePath := filepath.Join(s.LibFolder, fileName)
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

	// Get file size for history
	fi, _ := os.Stat(filePath)
	fileSize := fi.Size()

	// If this is Maya 2024, also copy to generic mk.zip for backward compatibility
	if mayaVersion == "2024" {
		genericPath := filepath.Join(s.LibFolder, s.LatestFile)
		srcFile, err := os.Open(filePath)
		if err == nil {
			defer srcFile.Close()
			dstFile, err := os.Create(genericPath)
			if err == nil {
				defer dstFile.Close()
				io.Copy(dstFile, srcFile)
				slog.Info("Also updated generic mk.zip for backward compatibility")
			}
		}
	}

	// Record in upload history
	q := dbgen.New(s.DB)
	q.AddUploadHistory(r.Context(), dbgen.AddUploadHistoryParams{
		FileName:    fileName,
		FileSize:    fileSize,
		UploadedAt:  time.Now(),
		MayaVersion: mayaVersionPtr,
	})
	// Trim history to last 100 entries
	q.TrimUploadHistory(r.Context())

	slog.Info("Uploaded new file", "path", filePath, "size", fileSize, "maya_version", mayaVersion)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"message": "File uploaded successfully", "filename": "%s", "maya_version": "%s"}`, fileName, mayaVersion)))
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
		url.QueryEscape(s.BaseURL+"/callback"),
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
		"redirect_uri":  {s.BaseURL + "/callback"},
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
		Email   string `json:"email"`
		Picture string `json:"picture"`
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
		Picture:   &userData.Picture,
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

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
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

	http.Redirect(w, r, "/logged-out", http.StatusTemporaryRedirect)
}

func (s *Server) HandleLoggedOut(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles(filepath.Join(s.TemplatesDir, "logged-out.html"))
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
}

type SessionInfo struct {
	Email   string
	Picture string
}

func (s *Server) getSession(r *http.Request) *SessionInfo {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	q := dbgen.New(s.DB)
	session, err := q.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}
	picture := ""
	if session.Picture != nil {
		picture = *session.Picture
	}
	return &SessionInfo{Email: session.Email, Picture: picture}
}

func (s *Server) getSessionEmail(r *http.Request) string {
	si := s.getSession(r)
	if si == nil {
		return ""
	}
	return si.Email
}

type FileInfo struct {
	Exists      bool
	Size        string
	Modified    string
	MayaVersion string
}

func (s *Server) getFileInfo() FileInfo {
	filePath := filepath.Join(s.LibFolder, s.LatestFile)
	info, err := os.Stat(filePath)
	if err != nil {
		return FileInfo{Exists: false}
	}

	size := info.Size()
	var sizeStr string
	switch {
	case size >= 1024*1024:
		sizeStr = fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
	case size >= 1024:
		sizeStr = fmt.Sprintf("%.2f KB", float64(size)/1024)
	default:
		sizeStr = fmt.Sprintf("%d bytes", size)
	}

	return FileInfo{
		Exists:      true,
		Size:        sizeStr,
		Modified:    info.ModTime().Format("Jan 2, 2006 at 3:04 PM"),
		MayaVersion: "generic",
	}
}

func (s *Server) getAllVersionFileInfo() []FileInfo {
	var files []FileInfo

	// Check generic file
	if fi := s.getFileInfo(); fi.Exists {
		files = append(files, fi)
	}

	// Check version-specific files
	for version := range validMayaVersions {
		fileName := fmt.Sprintf("mk_%s.zip", version)
		filePath := filepath.Join(s.LibFolder, fileName)
		info, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		size := info.Size()
		var sizeStr string
		switch {
		case size >= 1024*1024:
			sizeStr = fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
		case size >= 1024:
			sizeStr = fmt.Sprintf("%.2f KB", float64(size)/1024)
		default:
			sizeStr = fmt.Sprintf("%d bytes", size)
		}

		files = append(files, FileInfo{
			Exists:      true,
			Size:        sizeStr,
			Modified:    info.ModTime().Format("Jan 2, 2006 at 3:04 PM"),
			MayaVersion: version,
		})
	}

	return files
}

func (s *Server) HandleAdmin(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	q := dbgen.New(s.DB)
	tokens, err := q.GetAllTokens(r.Context())
	if err != nil {
		http.Error(w, "Failed to get tokens", http.StatusInternalServerError)
		return
	}

	data := struct {
		Email        string
		Picture      string
		Tokens       []dbgen.GetAllTokensRow
		File         FileInfo
		FileName     string
		VersionFiles []FileInfo
	}{
		Email:        session.Email,
		Picture:      session.Picture,
		Tokens:       tokens,
		File:         s.getFileInfo(),
		FileName:     s.LatestFile,
		VersionFiles: s.getAllVersionFileInfo(),
	}

	tmpl, err := template.ParseFiles(filepath.Join(s.TemplatesDir, "admin.html"))
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func (s *Server) HandleAdminRegenerateToken(w http.ResponseWriter, r *http.Request) {
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

	newToken := generateToken()

	q := dbgen.New(s.DB)
	err = q.UpdateToken(r.Context(), dbgen.UpdateTokenParams{
		ID:    id,
		Token: newToken,
	})
	if err != nil {
		http.Error(w, "Failed to regenerate token", http.StatusInternalServerError)
		return
	}

	slog.Info("Token regenerated", "id", id, "by", email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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

	mayaVersions := r.Form["maya_versions"]
	if len(mayaVersions) == 0 {
		mayaVersions = []string{"2024", "2025", "2026"}
	}
	mayaVersionsStr := strings.Join(mayaVersions, ",")

	defaultMayaVersion := r.FormValue("default_maya_version")
	if defaultMayaVersion == "" {
		defaultMayaVersion = mayaVersions[0] // Default to first selected version
	}

	tokenValue := generateToken()

	q := dbgen.New(s.DB)
	_, err := q.CreateToken(r.Context(), dbgen.CreateTokenParams{
		Name:               name,
		Token:              tokenValue,
		TokenType:          "download",
		MayaVersions:       &mayaVersionsStr,
		DefaultMayaVersion: &defaultMayaVersion,
	})
	if err != nil {
		http.Error(w, "Failed to create token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("Token created", "name", name, "maya_versions", mayaVersionsStr, "by", email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func generateRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:n]
}

func (s *Server) HandlePackageDownload(w http.ResponseWriter, r *http.Request) {
	email := s.getSessionEmail(r)
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenName := r.PathValue("name")
	if tokenName == "" {
		http.Error(w, "Missing token name", http.StatusBadRequest)
		return
	}

	q := dbgen.New(s.DB)
	token, err := q.GetTokenByName(r.Context(), tokenName)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}

	if token.TokenType != "download" {
		http.Error(w, "Cannot generate package for upload token", http.StatusBadRequest)
		return
	}

	var mayaVersions []string
	if token.MayaVersions != nil && *token.MayaVersions != "" {
		mayaVersions = strings.Split(*token.MayaVersions, ",")
	}
	if len(mayaVersions) == 0 {
		mayaVersions = []string{"2024", "2025", "2026"}
	}

	defaultMayaVersion := "2024"
	if token.DefaultMayaVersion != nil && *token.DefaultMayaVersion != "" {
		defaultMayaVersion = *token.DefaultMayaVersion
	}

	// Generate the package
	zipData, err := s.generatePackage(tokenName, token.Token, mayaVersions, defaultMayaVersion)
	if err != nil {
		slog.Error("Failed to generate package", "error", err)
		http.Error(w, "Failed to generate package: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_workspace.zip", tokenName))
	w.Write(zipData)
}

func (s *Server) generatePackage(tokenName, tokenValue string, mayaVersions []string, defaultMayaVersion string) ([]byte, error) {
	templateDir := "/home/exedev/hubv2/templates"

	// Check if template exists
	if _, err := os.Stat(filepath.Join(templateDir, "Tools")); os.IsNotExist(err) {
		return nil, fmt.Errorf("template not found - please upload CLIENT_WORKSPACE_TEMPLATE.zip first")
	}

	// Create a buffer to write the zip to
	var buf strings.Builder
	zipWriter := zip.NewWriter(&writerAdapter{&buf})

	// Walk through the template directory
	err := filepath.Walk(templateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the zip file itself
		if strings.HasSuffix(path, ".zip") {
			return nil
		}

		// Skip the latest file in bin/
		if strings.HasSuffix(path, "bin/latest") || strings.HasSuffix(path, "bin\\latest") {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(templateDir, path)
		if err != nil {
			return err
		}

		// Handle the .mod file rename
		if strings.HasSuffix(relPath, "newclient.mod") {
			relPath = strings.Replace(relPath, "newclient.mod", tokenName+".mod", 1)
		}

		// Handle the pbp folder rename to token name
		if strings.Contains(relPath, "scripts/pbp") || strings.Contains(relPath, "scripts\\pbp") {
			relPath = strings.Replace(relPath, "scripts/pbp", "scripts/"+tokenName, 1)
			relPath = strings.Replace(relPath, "scripts\\pbp", "scripts\\"+tokenName, 1)
		}

		// Handle shelf file rename (PBP -> tokenName)
		if strings.Contains(relPath, "shelf_PBP_") {
			relPath = strings.Replace(relPath, "shelf_PBP_", "shelf_"+tokenName+"_", 1)
		}



		if info.IsDir() {
			if relPath != "." {
				_, err := zipWriter.Create(relPath + "/")
				return err
			}
			return nil
		}

		// Create file in zip
		writer, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		// Handle special files
		baseName := filepath.Base(path)
		switch {
		case baseName == "token":
			// Write the token value
			_, err = writer.Write([]byte(tokenValue))
			return err

		case baseName == "newclient.mod":
			// Generate .mod file content
			modContent := s.generateModContent(tokenName, mayaVersions)
			_, err = writer.Write([]byte(modContent))
			return err

		case baseName == "settings.py":
			// Modify settings.py
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			modified := strings.Replace(string(content), "NEW CLIENT MAYA TOOLS", tokenName, 1)
			modified = strings.Replace(modified, "NewClientModule", tokenName+"_module", 1)
			_, err = writer.Write([]byte(modified))
			return err

		case baseName == "startup.py":
			// Replace PBP references in startup.py
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			modified := strings.ReplaceAll(string(content), "PBP", strings.ToUpper(tokenName))
			_, err = writer.Write([]byte(modified))
			return err

		case strings.HasPrefix(baseName, "shelf_PBP_") && strings.HasSuffix(baseName, ".mel"):
			// Replace PBP/pbp references in shelf mel files
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			modified := strings.ReplaceAll(string(content), "shelf_PBP_", "shelf_"+tokenName+"_")
			modified = strings.ReplaceAll(modified, "pbp.", tokenName+".")
			modified = strings.ReplaceAll(modified, "pbp_module", tokenName+"_module")
			_, err = writer.Write([]byte(modified))
			return err

		case baseName == "Launch Maya.bat":
			// Modify Launch Maya.bat with default Maya version and local requirements path
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			modified := string(content)
			// Replace the version on line 4
			modified = strings.Replace(modified, `set "version=2024"`, `set "version=`+defaultMayaVersion+`"`, 1)
			// Replace the requirements.txt path to use local path
			modified = strings.Replace(modified, `"R:\Tools\Maya\requirements.txt"`, `"%maya_root_path%\requirements.txt"`, 1)
			_, err = writer.Write([]byte(modified))
			return err

		default:
			// Copy file as-is
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(writer, file)
			return err
		}
	})

	if err != nil {
		return nil, err
	}

	if err := zipWriter.Close(); err != nil {
		return nil, err
	}

	return []byte(buf.String()), nil
}

func (s *Server) generateModContent(tokenName string, mayaVersions []string) string {
	var blocks []string
	for _, version := range mayaVersions {
		block := fmt.Sprintf("+ MAYAVERSION:%s %s_module 1.0.0 .\r\nMAYA_SHELF_PATH+:=shelves\r\nMAYA_NO_WARNING_FOR_MISSING_DEFAULT_RENDERER=1\r\nMAYA_CM_DISABLE_ERROR_POPUPS=1", version, tokenName)
		blocks = append(blocks, block)
	}
	return strings.Join(blocks, "\r\n\r\n") + "\r\n"
}

// writerAdapter adapts strings.Builder to io.Writer
type writerAdapter struct {
	b *strings.Builder
}

func (w *writerAdapter) Write(p []byte) (n int, err error) {
	return w.b.Write(p)
}

func (s *Server) HandleUploadHistory(w http.ResponseWriter, r *http.Request) {
	email := s.getSessionEmail(r)
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	q := dbgen.New(s.DB)
	history, err := q.GetUploadHistory(r.Context(), 100)
	if err != nil {
		http.Error(w, "Failed to get history", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func (s *Server) HandleUploadTemplate(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token != s.getUploadToken() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Invalid token"}`))
		return
	}

	if err := r.ParseMultipartForm(64 << 20); err != nil {
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

	templatesDir := "/home/exedev/hubv2/templates"
	os.MkdirAll(templatesDir, 0755)
	filePath := filepath.Join(templatesDir, "CLIENT_WORKSPACE_TEMPLATE.zip")

	dst, err := os.Create(filePath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Failed to create file"}`))
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Failed to save file"}`))
		return
	}

	slog.Info("Uploaded template", "path", filePath)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "Template uploaded successfully"}`))
}

func (s *Server) Serve(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.HandleRoot)
	mux.HandleFunc("GET /download/latest", s.HandleDownloadLatest)
	mux.HandleFunc("POST /upload/latest", s.HandleUploadLatest)
	mux.HandleFunc("POST /upload/template", s.HandleUploadTemplate)
	mux.HandleFunc("GET /upload/history", s.HandleUploadHistory)
	mux.HandleFunc("GET /package/{name}", s.HandlePackageDownload)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join(s.TemplatesDir, "..", "static")))))

	// Admin routes
	mux.HandleFunc("GET /login", s.HandleAdminLogin)
	mux.HandleFunc("GET /callback", s.HandleAdminCallback)
	mux.HandleFunc("GET /logout", s.HandleAdminLogout)
	mux.HandleFunc("GET /logged-out", s.HandleLoggedOut)
	mux.HandleFunc("POST /token/regenerate", s.HandleAdminRegenerateToken)
	mux.HandleFunc("POST /token/create", s.HandleAdminCreateToken)
	mux.HandleFunc("POST /token/delete", s.HandleAdminDeleteToken)

	slog.Info("starting server", "addr", addr)
	return http.ListenAndServe(addr, mux)
}
