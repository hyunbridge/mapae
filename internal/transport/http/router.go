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

type HealthResponse struct {
	Status  string `json:"status"`
	Storage string `json:"storage"`
}

type ErrorResponse struct {
	Detail string `json:"detail"`
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

// HealthHandler godoc
// @Summary      Health Check
// @Description  서버/스토리지 상태 확인
// @Tags         system
// @Produce      json
// @Success      200  {object}  HealthResponse
// @Failure      503  {object}  HealthResponse
// @Router       /health [get]
func (s *Server) healthHandler(c echo.Context) error {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
	defer cancel()
	if err := s.auth.Ping(ctx); err != nil {
		return c.JSON(http.StatusServiceUnavailable, HealthResponse{Status: "unhealthy", Storage: "down"})
	}
	return c.JSON(http.StatusOK, HealthResponse{Status: "ok", Storage: "up"})
}

// AuthInitHandler godoc
// @Summary      인증 시작
// @Description  인증 요청 생성
// @Tags         auth
// @Produce      json
// @Success      200  {object}  auth.AuthInitResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/init [post]
func (s *Server) authInitHandler(c echo.Context) error {
	resp, err := s.auth.InitAuth(c.Request().Context())
	if err != nil {
		s.logger.Printf("auth init error: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Detail: "서버 오류가 발생했습니다"})
	}
	return c.JSON(http.StatusOK, resp)
}

// AuthCheckHandler godoc
// @Summary      인증 상태 조회
// @Description  인증 완료 여부 조회
// @Tags         auth
// @Produce      json
// @Param        auth_id   path      string  true  "인증 ID"
// @Success      200       {object}  auth.AuthCheckResponse
// @Failure      400       {object}  ErrorResponse
// @Failure      500       {object}  ErrorResponse
// @Router       /auth/check/{auth_id} [get]
func (s *Server) authCheckHandler(c echo.Context) error {
	authID := strings.TrimSpace(c.Param("auth_id"))
	if authID == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Detail: "유효하지 않은 auth_id 입니다"})
	}
	resp, err := s.auth.CheckAuth(c.Request().Context(), authID)
	if err != nil {
		if err == auth.ErrInvalidAuthID {
			return c.JSON(http.StatusBadRequest, ErrorResponse{Detail: "유효하지 않은 auth_id 입니다"})
		}
		s.logger.Printf("auth check error: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Detail: "서버 오류가 발생했습니다"})
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
