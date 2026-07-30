package httpapi

import (
	"net/http"
	"strings"

	"github.com/HarAlb/golang-micro-shared/internal/jwt"
	"github.com/gin-gonic/gin"
)

type contextKey string

const userIdContextKey contextKey = "userID"

func AuthMiddleware(jwtManager jwt.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or malformed authorization header"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, prefix)

		claims, err := jwtManager.ParseToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		// кладём userID в gin.Context, доступно во всех последующих хендлерах этой цепочки
		c.Set(userIdContextKey, claims.UserID)
		c.Next()
	}
}

func UserIDFromContext(c *gin.Context) (int64, bool) {
	val, exists := c.Get(userIdContextKey)
	if !exists {
		return 0, false
	}
	userID, ok := val.(int64)
	return userID, ok
}
