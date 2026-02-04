package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mapae/internal/auth"
	"mapae/internal/config"
	"mapae/internal/logging"
	"mapae/internal/storage"
	"mapae/internal/storage/memory"
	"mapae/internal/storage/redis"
	httpapi "mapae/internal/transport/http"
	"mapae/internal/transport/smtp"
)

func main() {
	settings := config.Load()
	logger := logging.New("mapae: ", settings.Debug)

	var store storage.Store
	redisURL := strings.TrimSpace(settings.RedisURL)
	if settings.UseInMemoryStore || redisURL == "" {
		memStore, err := memory.New()
		if err != nil {
			logger.Printf("Failed to initialize in-memory store: %v", err)
			os.Exit(1)
		}
		store = memStore
		logger.Printf("Using in-memory store")
	} else {
		redisClient, err := redis.New(redisURL)
		if err != nil {
			logger.Printf("Failed to initialize Redis client: %v", err)
			os.Exit(1)
		}
		store = redisClient
		logger.Printf("Using Redis store")
	}
	authService := auth.New(store, settings)

	httpServer := httpapi.NewServer(settings, authService, logger)
	smtpServer := smtp.NewServer(settings, authService, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := smtpServer.Run(ctx); err != nil {
			logger.Printf("SMTP server stopped: %v", err)
		}
	}()

	httpAddr := fmt.Sprintf("%s:%d", settings.HTTPHost, settings.HTTPPort)
	server := &http.Server{
		Addr:    httpAddr,
		Handler: httpServer.Handler(),
	}

	go func() {
		logger.Printf("HTTP server listening on %s", httpAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Printf("HTTP server error: %v", err)
			cancel()
		}
	}()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	<-signalCh
	logger.Printf("Shutting down...")
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
}
