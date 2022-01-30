package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/likexian/gokit/assert"
	log "github.com/sirupsen/logrus"
)

// These are not complete tests of all functions in elixir. New tests should
// be added as the code is updated.

func TestRemoveHost(t *testing.T) {
	if removeHost("test1") != "test1" {
		t.Error("removeHost should return the input string when given 'test1'")
	}
	if removeHost("test2@test.com") != "test2" {
		t.Error("removeHost should return 'test2' when given 'test2@test.com'")
	}
	if removeHost("test3@test@test.com") != "test3" {
		t.Error("removeHost should return 'test3' when given " +
			"'test3@test@test.com'")
	}
}

func TestRSA(t *testing.T) {
	var (
		EGAclaims jwt.MapClaims
		JWTRSAalg = "RS256"
	)
	// Create RSA private key on the fly
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create("keys/sign-rsa-jwt.key")
	assert.Nil(t, err)
	err = pem.Encode(privatePem, privateKeyBlock)
	assert.Nil(t, err)

	jwtPrKey := "keys/sign-rsa-jwt.key"
	jwtSignatureAlg := JWTRSAalg
	elixirJWT := "eyJhbGciOiJIUzI1NiIsImtpZCI6InJzYTEiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiI0ZjdkZjAyNWQzYzhjNmM2NDVhOGJlM2U2ZDQyYjU3ODlmZmM5NTNlQGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiNGU5NDE2YTctMzUxNS00NDdhLWI4NDgtZDRhYzdjYWJhNTdmIiwiYXV0aF90aW1lIjoxNjMxNzkwMTgzLCJraWQiOiJyc2ExIiwiaXNzIjoiaHR0cHM6XC9cL2xvZ2luLmVsaXhpci1jemVjaC5vcmdcL29pZGNcLyIsImV4cCI6MTYzMTc5MDc5NCwiaWF0IjoxNjMxNzkwMTkzLCJqdGkiOiIyN2ZlM2M0Yy1lMTJiLTQ2ZTYtYjlkZC1mMTVlMjg4MDM4ZTEifQ.ecPJN2F3sPhmYZXJS8i3JD93wnzbTq9Ot9P0xCtun8zZJMvyCumWqAyjFgx_kawR2QS9XdS4kC0fOxSrnKP5H_jUWC61OjfdD7acp4nfPrqtYeCm6cYCanUAjdAVA7dS-W8_DC41WlkV-jd22di1Jyystz45HJ-o_xrlCo6BKUa-CsgylyUxWjEta6XTWAw5ZhAedOH2tmDG3S7rNwpEVICjqwPjLL62qmLlXB_ZlhZhWA1oK0rjNZ9GurXt41KcOPuGNvQU1v5_a8qQ_CSTtnhSWFPIw6jBrZ5jkFNj7-vqRDGz2Ae5cvwmm-G7LE9Yo-cbptKa01sOhijTvGq01A"
	idStruct := ElixirIdentity{
		User:     "",
		Token:    elixirJWT,
		Passport: nil,
		Profile:  "Dummy Tester",
		Email:    "dummy.tester@gs.uu.se",
	}
	tokenEGA, err := generateJwtFromElixir(idStruct, jwtPrKey, jwtSignatureAlg, "http://test.login.org/elixir/login")
	assert.Nil(t, err)
	token, _ := jwt.Parse(tokenEGA, func(tokenEGA *jwt.Token) (interface{}, error) { return nil, nil })
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		EGAclaims = claims
	} else {
		log.Error("Claims in token are empty")
	}

	expDateStr := fmt.Sprintf("%.0f", EGAclaims["exp"])
	expDateInt, err := strconv.ParseInt(expDateStr, 10, 64)
	if err != nil {
		panic(err)
	}

	expDate := time.Unix(expDateInt, 0)
	tenDays := time.Now().UTC().Add(240 * time.Hour)
	sixDays := time.Now().Add(144 * time.Hour)

	if expDate.Before(tenDays) == false || expDate.After(sixDays) == false {
		t.Error("token expires out of range")
	}

	if EGAclaims["name"] != idStruct.Profile {
		t.Error("name of the user is not correct")
	}

	if EGAclaims["email"] != idStruct.Email {
		t.Error("email of the user is not correct")
	}

	defer os.Remove("keys/sign-rsa-jwt.key")
}

func TestEC(t *testing.T) {
	var (
		EGAclaims jwt.MapClaims
		JWTalg = "ES256"
	)
	// Create ECDSA private key on the fly
	privatekey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)
	ecder, err := x509.MarshalECPrivateKey(privatekey)
	assert.Nil(t, err)
	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecder,
	}
	privatePem, err := os.Create("keys/sign-ecdsa-jwt.key")
	assert.Nil(t, err)
	err = pem.Encode(privatePem, privateKeyBlock)
	assert.Nil(t, err)

	jwtPrKey := "keys/sign-ecdsa-jwt.key"
	elixirJWT := "eyJhbGciOiJIUzI1NiIsImtpZCI6InJzYTEiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiI0ZjdkZjAyNWQzYzhjNmM2NDVhOGJlM2U2ZDQyYjU3ODlmZmM5NTNlQGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiNGU5NDE2YTctMzUxNS00NDdhLWI4NDgtZDRhYzdjYWJhNTdmIiwiYXV0aF90aW1lIjoxNjMxNzkwMTgzLCJraWQiOiJyc2ExIiwiaXNzIjoiaHR0cHM6XC9cL2xvZ2luLmVsaXhpci1jemVjaC5vcmdcL29pZGNcLyIsImV4cCI6MTYzMTc5MDc5NCwiaWF0IjoxNjMxNzkwMTkzLCJqdGkiOiIyN2ZlM2M0Yy1lMTJiLTQ2ZTYtYjlkZC1mMTVlMjg4MDM4ZTEifQ.ecPJN2F3sPhmYZXJS8i3JD93wnzbTq9Ot9P0xCtun8zZJMvyCumWqAyjFgx_kawR2QS9XdS4kC0fOxSrnKP5H_jUWC61OjfdD7acp4nfPrqtYeCm6cYCanUAjdAVA7dS-W8_DC41WlkV-jd22di1Jyystz45HJ-o_xrlCo6BKUa-CsgylyUxWjEta6XTWAw5ZhAedOH2tmDG3S7rNwpEVICjqwPjLL62qmLlXB_ZlhZhWA1oK0rjNZ9GurXt41KcOPuGNvQU1v5_a8qQ_CSTtnhSWFPIw6jBrZ5jkFNj7-vqRDGz2Ae5cvwmm-G7LE9Yo-cbptKa01sOhijTvGq01A"
	idStruct := ElixirIdentity{
		User:     "",
		Token:    elixirJWT,
		Passport: nil,
		Profile:  "Dummy Tester",
		Email:    "dummy.tester@gs.uu.se",
	}
	tokenEGA, err := generateJwtFromElixir(idStruct, jwtPrKey, JWTalg, "http://test.login.org/elixir/login")
	assert.Nil(t, err)

	token, _ := jwt.Parse(tokenEGA, func(tokenEGA *jwt.Token) (interface{}, error) { return nil, nil })
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		EGAclaims = claims
	} else {
		log.Error("Claims in token are empty")
	}

	expDateStr := fmt.Sprintf("%.0f", EGAclaims["exp"])
	expDateInt, err := strconv.ParseInt(expDateStr, 10, 64)
	if err != nil {
		panic(err)
	}

	expDate := time.Unix(expDateInt, 0)
	tenDays := time.Now().UTC().Add(240 * time.Hour)
	sixDays := time.Now().Add(144 * time.Hour)

	if expDate.Before(tenDays) == false || expDate.After(sixDays) == false {
		t.Error("token expires out of range")
	}

	if EGAclaims["name"] != idStruct.Profile {
		t.Error("name of the user is not correct")
	}

	if EGAclaims["email"] != idStruct.Email {
		t.Error("email of the user is not correct")
	}

	defer os.Remove("keys/sign-ecdsa-jwt.key")
}
