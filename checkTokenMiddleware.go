package tokenauth

import (
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

const tokenHeader = "token"
const TokenDataContextKey = "tokenData"

var pathToExclude = []string{"/refreshToken", "/connect"}

func CheckTokenMiddleware(baseToken TokenBase) gin.HandlerFunc {
	return func(c *gin.Context) {
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
