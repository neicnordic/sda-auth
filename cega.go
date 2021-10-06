package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
	bcrypt "golang.org/x/crypto/bcrypt"
)

// EGALoginError is used to store message errors
type EGALoginError struct {
	Reason string
}

// CegaUserResponse captures the response key
type CegaUserResponse struct {
	Results CegaUserResults `json:"response"`
}

// CegaUserResults captures the result key
type CegaUserResults struct {
	Response []CegaUserInfo `json:"result"`
}

// CegaUserInfo captures the password hash
type CegaUserInfo struct {
	PasswordHash string `json:"passwordHash"`
}

// EGAIdentity represents an EGA user instance
type EGAIdentity struct {
	User  string
	Token string
}

// Return base64 encoded credentials for basic auth
func getb64Credentials(username, password string) string {
	creds := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(creds))
}

// Check whether the returned hash corresponds to the given password
func verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Return base64 encoded credentials for basic auth
func generateJwtToken(issuer, sub, key, alg string) string {
	// Create a new token object by specifying signing method and the needed claims

	ttl := 200 * time.Hour
	token := jwt.NewWithClaims(jwt.GetSigningMethod(alg), &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(ttl)),
		Issuer:    issuer,
		Subject:   sub,
	})
	data, err := ioutil.ReadFile(key)
	var tokenString string

	switch alg {
	case "ES256":
		pk, err := jwt.ParseECPrivateKeyFromPEM(data)
		if err != nil {
			log.Fatal(err, pk)
		}
		tokenString, err = token.SignedString(pk)
		if err != nil {
			log.Fatal(err, pk)
		}
	case "RS256":
		pk, err := jwt.ParseRSAPrivateKeyFromPEM(data)
		if err != nil {
			log.Fatal(err, pk)
		}
		tokenString, err = token.SignedString(pk)
		if err != nil {
			log.Fatal(err, pk)
		}
	}

	if err != nil {
		log.Fatal(err, tokenString)
	}
	// Sign and get the complete encoded token
	if err != nil {
		log.Error("Token could not be fetched: ", err)
	}
	return tokenString
}

// Authenticate against CEGA
func authenticateWithCEGA(conf CegaConfig, username string) (*http.Response, error) {
	client := &http.Client{}
	payload := strings.NewReader("")
	req, err := http.NewRequest("GET", fmt.Sprintf("%s%s?idType=username", conf.authURL, username), payload)

	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("Authorization", "Basic "+getb64Credentials(conf.id, conf.secret))
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)

	return res, err
}
