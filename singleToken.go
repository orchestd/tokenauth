package tokenauth

import (
	"fmt"
	"github.com/golang-jwt/jwt"
)

func (jwtToken jwtToken) SignPayload(plainData jwt.MapClaims) (string, error) {
	return jwtToken.signPayload(plainData)
}

func (jwtToken jwtToken) VerifyPayload(token string) (jwt.MapClaims, error) {
	return jwtToken.verifyPayload(token)
}

func (jwtToken jwtToken) signPayload(claims jwt.MapClaims) (string, error) {
	encryptKey := jwtToken.credentials.GetCredentials().EncryptKey
	if encryptKey == "" {
		return "", fmt.Errorf("could not get credentials by key encryptKey")
	}
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret, err := jwtToken.getSecret()
	if err != nil {
		return "", err
	}
	token, err := at.SignedString(secret)
	return token, err
}

func (jwtToken jwtToken) verifyPayload(token string) (jwt.MapClaims, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
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
		return nil, err
	}
	atClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return atClaims, nil
}
