package tokenauth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/orchestd/dependencybundler/interfaces/cache"
	"github.com/orchestd/dependencybundler/interfaces/credentials"
	"github.com/orchestd/serviceerror"
	"github.com/orchestd/sharedlib/encryption"
	"time"
)

var jwtSecretFirst = fmt.Sprint("tok", 2021, []byte("65"))

const accessTokenLifeTimeMin = 5
const refreshTokenLifeTimeMin = 2 * 365 * 24 * 60
const plainDataClaim = "plainData"
const dataClaim = "data"
const refreshTokensCollectionName = "refreshTokens"

//must have this name
const expClaim = "exp"
const iatClaim = "iat"

type RefreshToken struct {
	IssuedAt *time.Time
	UsedAt   *time.Time
}

func NewJwtToken(credentials credentials.CredentialsGetter, cacheGetter cache.CacheStorageGetter, cacheSetter cache.CacheStorageSetter) TokenBase {
	return jwtToken{credentials: credentials, cacheGetter: cacheGetter, cacheSetter: cacheSetter}
}

type jwtToken struct {
	credentials credentials.CredentialsGetter
	cacheGetter cache.CacheStorageGetter
	cacheSetter cache.CacheStorageSetter
}

func (jwtToken jwtToken) getSecret() ([]byte, error) {
	jwtSecret := jwtToken.credentials.GetCredentials().JwtSecret
	if jwtSecret == "" {
		return nil, fmt.Errorf("could not get credentials by key jwt_secret")
	}
	return []byte(jwtSecretFirst + jwtSecret), nil
}

func (jwtToken jwtToken) createToken(now time.Time, lifeTimeMin int64, sessionId string, customerId string,
	protectedData map[string]interface{}, plainData map[string]interface{}) (string, error) {
	encryptKey := jwtToken.credentials.GetCredentials().EncryptKey
	if encryptKey == "" {
		return "", fmt.Errorf("could not get credentials by key encryptKey")
	}
	atClaims := jwt.MapClaims{}
	protectedData["sessionId"] = sessionId
	protectedData["customerId"] = customerId
	protectedDataJson, err := json.Marshal(protectedData)
	if err != nil {
		return "", fmt.Errorf("can't marshal protectedData. " + err.Error())
	}
	plainDataJson, err := json.Marshal(plainData)
	if err != nil {
		return "", fmt.Errorf("can't marshal plainData. " + err.Error())
	}
	encryptedData, err := encryption.EncryptBase64AES(protectedDataJson, encryptKey)
	if err != nil {
		return "", fmt.Errorf("can't encrypt protected data. " + err.Error())
	}
	atClaims[plainDataClaim] = string(plainDataJson)
	atClaims[dataClaim] = encryptedData
	expiredAt := now.Add(time.Minute * time.Duration(lifeTimeMin))
	atClaims[expClaim] = expiredAt.Unix()
	atClaims[iatClaim] = now.Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	secret, err := jwtToken.getSecret()
	if err != nil {
		return "", err
	}
	token, err := at.SignedString(secret)
	return token, err
}

func (jwtToken jwtToken) CreateTokensPair(c context.Context, now time.Time, sessionId string, customerId string, protectedData map[string]interface{}, plainData map[string]interface{}) (string, string, error) {
	refreshTokenUuid := uuid.New().String()

	protectedData["refreshTokenUuid"] = refreshTokenUuid
	accessToken, err := jwtToken.createToken(now, accessTokenLifeTimeMin, sessionId, customerId, protectedData, plainData)
	if err != nil {
		return "", "", fmt.Errorf("can't create asscess token. " + err.Error())
	}

	protectedData["uuid"] = refreshTokenUuid
	refreshToken, err := jwtToken.createToken(now, refreshTokenLifeTimeMin, sessionId, customerId, protectedData, plainData)

	if err != nil {
		return "", "", fmt.Errorf("can't create refresh token. " + err.Error())
	}

	refreshTokenData := RefreshToken{IssuedAt: &now}

	cacheErr := jwtToken.cacheSetter.Insert(c, refreshTokensCollectionName, refreshTokenUuid, "1", refreshTokenData)
	if cacheErr != nil {
		return "", "", fmt.Errorf("can't add refresh token to cache. " + cacheErr.Error())
	}
	return accessToken, refreshToken, nil
}

func (jwtToken jwtToken) ValidateAndGetData(c context.Context, now time.Time, token string) (map[string]interface{}, map[string]interface{}, error) {
	jwt.TimeFunc = func() time.Time {
		return now
	}
	var plainData map[string]interface{}
	var protectedData map[string]interface{}
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		secret, err := jwtToken.getSecret()
		if err != nil {
			return "", err
		}
		return secret, nil
	})
	if err != nil {
		return nil, nil, err
	}
	atClaims := parsedToken.Claims.(jwt.MapClaims)
	encryptKey := jwtToken.credentials.GetCredentials().EncryptKey
	if encryptKey == "" {
		return nil, nil, fmt.Errorf("could not get credentials by key encryptKey")
	}

	err = json.Unmarshal([]byte(atClaims[plainDataClaim].(string)), &plainData)
	if err != nil {
		return nil, nil, fmt.Errorf("can't unmarshal plain data. " + err.Error())
	}

	encryptedData := atClaims[dataClaim].(string)
	decryptedData, err := encryption.DecryptBase64AES([]byte(encryptedData), encryptKey)
	if err != nil {
		return nil, nil, fmt.Errorf("can't dycript data. " + err.Error())
	}
	err = json.Unmarshal([]byte(decryptedData), &protectedData)
	if err != nil {
		return nil, nil, fmt.Errorf("can't unmarshal plain data. " + err.Error())
	}
	return plainData, protectedData, nil
}

func (jwtToken jwtToken) RemoveRefreshToken(c context.Context, now time.Time, token string) error {
	_, protectedData, err := jwtToken.ValidateAndGetData(c, now, token)
	if err != nil {
		return err
	}
	refreshTokenUuid := protectedData["uuid"].(string)
	err = jwtToken.cacheSetter.Remove(c, refreshTokensCollectionName, refreshTokenUuid, "1")
	if err != nil {
		return fmt.Errorf("can't remove refresh token from cache." + err.Error())
	}
	return nil
}

func (jwtToken jwtToken) ValidateAndUseRefreshToken(c context.Context, now time.Time, token string) (map[string]interface{}, map[string]interface{}, error) {
	plainData, protectedData, err := jwtToken.ValidateAndGetData(c, now, token)
	if err != nil {
		return nil, nil, err
	}
	refreshTokenUuid := protectedData["uuid"].(string)
	refreshToken := RefreshToken{}
	err = jwtToken.cacheGetter.GetById(c, refreshTokensCollectionName, refreshTokenUuid, "1", &refreshToken)
	if err != nil {
		return nil, nil, fmt.Errorf("can't get refresh token from cache." + err.Error())
	}
	if refreshToken.IssuedAt == nil || refreshToken.UsedAt != nil {
		return nil, nil, fmt.Errorf("%w: %q", serviceerror.SecurityError, fmt.Errorf("token has already been used"))
	}

	refreshToken.UsedAt = &now
	err = jwtToken.cacheSetter.Update(c, refreshTokensCollectionName, refreshTokenUuid, "1", refreshToken)
	if err != nil {
		return nil, nil, fmt.Errorf("can't update refresh token from cache." + err.Error())
	}

	return plainData, protectedData, nil
}

func (jwtToken jwtToken) RemoveRefreshTokenById(c context.Context, id string) error {
	err := jwtToken.cacheSetter.Remove(c, refreshTokensCollectionName, id, "1")
	if err != nil {
		return fmt.Errorf("can't remove refresh token from cache." + err.Error())
	}
	return nil
}
