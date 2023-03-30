package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jws"
	log "github.com/sirupsen/logrus"
)

type Claims struct {
	Email string `json:"email,omitempty"`
	KeyID string `json:"kid,omitempty"`
	jwt.RegisteredClaims
}

func generateJwtToken(claims *Claims, key, alg string) (string, string, error) {
	// Create a new token object by specifying signing method and the needed claims
	ttl := 200 * time.Hour
	expireDate := time.Now().UTC().Add(ttl)
	claims.ExpiresAt = jwt.NewNumericDate(expireDate)

	token := jwt.NewWithClaims(jwt.GetSigningMethod(alg), claims)

	data, err := os.ReadFile(key)
	if err != nil {
		return "", "", fmt.Errorf("Failed to read signingkey, reason: %v", err)
	}
	claims.KeyID = fmt.Sprintf("%x", sha256.Sum256(data))

	var tokenString string
	switch alg {
	case "ES256":
		pk, err := jwt.ParseECPrivateKeyFromPEM(data)
		if err != nil {
			return "", "", err
		}
		tokenString, err = token.SignedString(pk)
		if err != nil {
			return "", "", err
		}
	case "RS256":
		pk, err := jwt.ParseRSAPrivateKeyFromPEM(data)
		if err != nil {
			return "", "", err
		}
		tokenString, err = token.SignedString(pk)
		if err != nil {
			return "", "", err
		}
	}

	return tokenString, expireDate.Format("2006-01-02 15:04:05"), nil
}

// validateTrustedIss searches a nested list of TrustedISS looking for an iss match.
// If found, it returns true and the corresponding jku pair entry in the list.
// If the list is nil it returns true, as the path for the trusted issue file was not set.
// inspired from sda-download
func validateTrustedIss(obj []TrustedISS, issuerValue string) (bool, string) {
	log.Debugf("check that token iss: %s is in our trusted list", issuerValue)
	if obj != nil {
		for _, value := range obj {
			if value.ISS == issuerValue {
				return true, value.JKU
			}
		}

		return false, ""
	}

	return true, ""
}

// helper function to read payload field values from a JWT
func readFromJWTpayload(token, field string) (interface{}, error) {
	m := make(map[string]interface{})
	msg, err := jws.ParseString(token)
	if err != nil {
		return "", fmt.Errorf("failed to parse token payload, reason: %v", err)
	}
	err = json.Unmarshal(msg.Payload(), &m)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal payload, reason: %v", err)
	}
	if _, ok := m[field]; !ok {
		return "", fmt.Errorf("failed to read value from field '%s'", field)
	}

	return m[field], nil
}

// checkTrustedIss checks that the token Issuer is in the trusted list and if yes
// it validates the token signature against the corresponding trusted jku
func checkTrustedIss(token string, trustedList []TrustedISS) error {

	// Skip checks if trustedIss file is empty.
	if trustedList == nil {
		return nil
	}

	tokenIssuer, err := readFromJWTpayload(token, "iss")
	if err != nil {
		return fmt.Errorf("failed to get issuer from token, reason: %v", err)
	}

	ok, tokenJku := validateTrustedIss(trustedList, tokenIssuer.(string))

	// token iss is not trusted
	if !ok {
		return fmt.Errorf("token issuer: '%s' is not in trusted list", tokenIssuer.(string))
	}

	// token signature cannot be validated against corresponding jku from file
	if _, err = validateToken(token, tokenJku); err != nil {
		return fmt.Errorf("failed to validate token with trusted issuer: %s against trusted jku, reason: %v", tokenIssuer.(string), err)
	}

	return nil
}
