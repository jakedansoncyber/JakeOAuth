package main

import (
	"JakeOAuth/auth"
	"JakeOAuth/handlers"
	"bytes"
	"io"
	"log"
	"net/http"
)

type JakeHandler struct{}

func (h *JakeHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	_, _ = w.Write([]byte("Hello world!"))
}

type LoggingMiddleware struct{}

func (lm *LoggingMiddleware) log(w http.ResponseWriter, req *http.Request) {
	log.Printf("Starting request for: %v\n", req.URL.Path)

	// Read the body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("Failed to read body: %v", err)
		return
	}

	// Log the body content
	log.Printf("Body: %s\n", string(body))

	// Restore the body so it can be read again in the handler
	req.Body = io.NopCloser(bytes.NewBuffer(body))
}

func Handlers(handler func(w http.ResponseWriter, req *http.Request)) {
	h := handler
	h(nil, nil)
}

type PostHandler struct {
	Handler    func(w http.ResponseWriter, req *http.Request)
	Middleware LoggingMiddleware
}

func (ph *PostHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ph.Middleware.log(w, req)
	ph.Handler(w, req)
	return
}

type GetHandler struct {
	Handler    func(w http.ResponseWriter, req *http.Request)
	Middleware LoggingMiddleware
}

func (gh *GetHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	// Handle preflight (OPTIONS) request
	if req.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	gh.Middleware.log(w, req)
	gh.Handler(w, req)
	return
}

func main() {
	h := handlers.NewAuthHandler(auth.NewAuthCodeStore())
	go h.CodeStore.ListenExpiration()
	authHandler := &GetHandler{
		Handler:    h.AuthorizationEndpointHandler,
		Middleware: LoggingMiddleware{},
	}

	initialRedirectHandler := &GetHandler{
		Handler:    handlers.HandleInitRedirect,
		Middleware: LoggingMiddleware{},
	}

	loginEndpointHandler := &GetHandler{
		Handler:    handlers.HandleLogin,
		Middleware: LoggingMiddleware{},
	}

	tokenEndpointHandler := &PostHandler{
		Handler:    h.TokenEndpointHandler,
		Middleware: LoggingMiddleware{},
	}

	hJ := JakeHandler{}
	http.Handle("/authorizationendpoint", authHandler)
	http.Handle("/tokenendpoint", tokenEndpointHandler)
	http.Handle("/initRedirect", initialRedirectHandler)
	http.Handle("/login", loginEndpointHandler)
	http.Handle("/home", &hJ)
	log.Println("Started on localhost:8080")
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}
