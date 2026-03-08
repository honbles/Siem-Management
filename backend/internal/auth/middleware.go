package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const ClaimsKey contextKey = "claims"

// Middleware validates the Authorization: Bearer <token> header.
func Middleware(jwt *JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}
			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}
			claims, err := jwt.Verify(parts[1])
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims extracts claims from context (set by Middleware).
func GetClaims(r *http.Request) *Claims {
	c, _ := r.Context().Value(ClaimsKey).(*Claims)
	return c
}
