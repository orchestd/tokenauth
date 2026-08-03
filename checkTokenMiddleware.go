package tokenauth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const tokenHeader = "token"
const TokenDataContextKey = "tokenData"
const UserClaimsContextKey = "userClaims"
const JwtContextKey = "jwt"
const AccessTokenCookieName = "AccessToken"

type PathToExcludeGetter interface {
	GetPathToExclude() []string
}

func CheckTokenMiddleware(baseToken TokenBase, pathToExcludeGetter PathToExcludeGetter) gin.HandlerFunc {
	return func(c *gin.Context) {
		pathToExclude := pathToExcludeGetter.GetPathToExclude()
		for _, p := range pathToExclude {
			if p == c.FullPath() {
				c.Next()
				return
			}
		}
		token := c.GetHeader(tokenHeader)
		plainData, protectedData, err := baseToken.ValidateAndGetData(context.Background(), time.Now(), token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"Message": "Unauthorized"})
			c.Abort()
			return
		}
		tokenData := make(map[string]interface{})
		for k, v := range plainData {
			tokenData[k] = v
		}
		for k, v := range protectedData {
			tokenData[k] = v
		}
		tokenDataJson, err := json.Marshal(tokenData)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"Message": "wrong data format"})
			c.Abort()
			return
		}
		ctx := context.WithValue(c.Request.Context(), TokenDataContextKey, string(tokenDataJson))
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func ValidateJWTMiddleware(tokenBase TokenBase) gin.HandlerFunc {
	return func(ginCtx *gin.Context) {
		cookie, err := ginCtx.Cookie(AccessTokenCookieName)
		if err != nil {
			ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization cookie"})
			return
		}

		claims, _, err := tokenBase.ValidateAndGetData(ginCtx.Request.Context(), time.Now(), cookie)

		ctx := context.WithValue(ginCtx.Request.Context(), UserClaimsContextKey, claims)
		ctx = context.WithValue(ctx, JwtContextKey, cookie)
		ginCtx.Request = ginCtx.Request.WithContext(ctx)
		ginCtx.Next()
	}
}

// Helper to safely pull claims out of context in business handlers
func ClaimsFromContext[T any](ctx context.Context) (*T, bool) {
	claimsany := ctx.Value(UserClaimsContextKey)
	if claimsany == nil {
		return nil, false
	}

	if claims, ok := claimsany.(T); ok {
		return &claims, true
	}

	bytes, err := json.Marshal(claimsany)
	if err != nil {
		return nil, false
	}

	var result T
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, false
	}

	return &result, true
}
