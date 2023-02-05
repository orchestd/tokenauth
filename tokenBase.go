package tokenauth

import (
	"context"
	"time"
)

type TokenBase interface {
	CreateTokensPair(c context.Context, now time.Time, sessionId string, customerId string, protectedData map[string]interface{}, plainData map[string]interface{}) (string, string, error)
	ValidateAndGetData(c context.Context, now time.Time, token string) (map[string]interface{}, map[string]interface{}, error)
	ValidateAndUseRefreshToken(c context.Context, now time.Time, token string) (map[string]interface{}, map[string]interface{}, error)
	RemoveRefreshToken(c context.Context, now time.Time, token string) error
	RemoveRefreshTokenById(c context.Context, id string) error
}
