package srv

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
)

type Server struct {
	LibFolder      string
	LatestFile     string
	UploadToken    string
	DownloadTokens []string
}

func New() (*Server, error) {
	libFolder := "/home/exedev/hubv2/lib"
	if err := os.MkdirAll(libFolder, 0755); err != nil {
		return nil, fmt.Errorf("create lib folder: %w", err)
	}

	uploadToken := os.Getenv("UPLOAD_TOKEN")
	if uploadToken == "" {
		return nil, fmt.Errorf("UPLOAD_TOKEN environment variable is required")
	}

	downloadTokens := []string{}
	if t := os.Getenv("DOWNLOAD_TOKEN_PLAYBYPAY"); t != "" {
		downloadTokens = append(downloadTokens, t)
	}
	if t := os.Getenv("DOWNLOAD_TOKEN_ADMIN"); t != "" {
		downloadTokens = append(downloadTokens, t)
	}

	return &Server{
		LibFolder:      libFolder,
		LatestFile:     "mk.zip",
		UploadToken:    uploadToken,
		DownloadTokens: downloadTokens,
	}, nil
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
	if token != s.UploadToken {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Invalid token"}`))
		return
	}

	// Parse multipart form (32MB max)
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
	for _, t := range s.DownloadTokens {
		if token == t {
			return true
		}
	}
	return false
}

func (s *Server) Serve(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.HandleRoot)
	mux.HandleFunc("GET /download/latest", s.HandleDownloadLatest)
	mux.HandleFunc("POST /upload/latest", s.HandleUploadLatest)
	slog.Info("starting server", "addr", addr)
	return http.ListenAndServe(addr, mux)
}
