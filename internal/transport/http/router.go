package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"mapae/internal/auth"
	"mapae/internal/config"
	"mapae/internal/logging"
)

type Server struct {
	settings *config.Settings
	auth     *auth.Service
	logger   *logging.Logger
	e        *echo.Echo
}

func NewServer(settings *config.Settings, authService *auth.Service, logger *logging.Logger) *Server {
	e := echo.New()
	e.HideBanner = true
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			origin := c.Request().Header.Get("Origin")
			if origin != "" && isAllowedOrigin(settings, origin) {
				res := c.Response()
				res.Header().Set("Access-Control-Allow-Origin", origin)
				res.Header().Set("Vary", "Origin")
				res.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
				res.Header().Set("Access-Control-Allow-Headers", "*")
			}
			if c.Request().Method == http.MethodOptions {
				return c.NoContent(http.StatusNoContent)
			}
			return next(c)
		}
	})

	server := &Server{settings: settings, auth: authService, logger: logger, e: e}
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogMethod:   true,
		LogURI:      true,
		LogStatus:   true,
		LogLatency:  true,
		LogRemoteIP: true,
		LogProtocol: true,
		LogValuesFunc: func(_ echo.Context, v middleware.RequestLoggerValues) error {
			server.logger.Printf(
				"INFO:     %s - %q %d %dms",
				v.RemoteIP,
				fmt.Sprintf("%s %s %s", v.Method, v.URI, v.Protocol),
				v.Status,
				v.Latency.Milliseconds(),
			)
			return nil
		},
	}))
	e.GET("/health", server.healthHandler)
	e.POST("/auth/init", server.authInitHandler)
	e.GET("/auth/check/:auth_id", server.authCheckHandler)
	return server
}

func (s *Server) Handler() http.Handler {
	return s.e
}

func (s *Server) healthHandler(c echo.Context) error {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
	defer cancel()
	if err := s.auth.Ping(ctx); err != nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]any{"status": "unhealthy", "storage": "down"})
	}
	return c.JSON(http.StatusOK, map[string]any{"status": "ok", "storage": "up"})
}

func (s *Server) authInitHandler(c echo.Context) error {
	resp, err := s.auth.InitAuth(c.Request().Context())
	if err != nil {
		s.logger.Printf("auth init error: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]any{"detail": "서버 오류가 발생했습니다"})
	}
	return c.JSON(http.StatusOK, resp)
}

func (s *Server) authCheckHandler(c echo.Context) error {
	authID := strings.TrimSpace(c.Param("auth_id"))
	if authID == "" {
		return c.JSON(http.StatusBadRequest, map[string]any{"detail": "유효하지 않은 auth_id 입니다"})
	}
	resp, err := s.auth.CheckAuth(c.Request().Context(), authID)
	if err != nil {
		if err == auth.ErrInvalidAuthID {
			return c.JSON(http.StatusBadRequest, map[string]any{"detail": "유효하지 않은 auth_id 입니다"})
		}
		s.logger.Printf("auth check error: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]any{"detail": "서버 오류가 발생했습니다"})
	}
	return c.JSON(http.StatusOK, resp)
}

func isAllowedOrigin(settings *config.Settings, origin string) bool {
	for _, allowed := range settings.CORSAllowOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}
