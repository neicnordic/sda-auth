package main

import (
	"io/ioutil"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// ElixirIdentity represents an Elixir user instance
type ElixirIdentity struct {
	User     string
	Passport []string
	Token    string
}

// Configure an OpenID Connect aware OAuth2 client.
func getOidcClient(conf ElixirConfig) (oauth2.Config, *oidc.Provider) {
	contx := context.Background()
	provider, err := oidc.NewProvider(contx, conf.issuer)
	if err != nil {
		log.Fatal(err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     conf.id,
		ClientSecret: conf.secret,
		RedirectURL:  conf.redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, conf.scope},
	}

	return oauth2Config, provider
}

// If the given string is formatted like <user>@<host>, only the <user> part is
// returned, otherwise the original string is returned.
// Note that this function will split on the first '@' symbol, and not the last
// like an e-mail parser would. This is to ensure that there are no @ signs in
// the returned username.
func removeHost(raw string) string {
	index := strings.Index(raw, "@")
	if index > -1 {
		return raw[:index]
	}
	return raw
}

// Authenticate with an Oidc client.against Elixir AAI
func authenticateWithOidc(oauth2Config oauth2.Config, provider *oidc.Provider, code string) (ElixirIdentity, error) {

	contx := context.Background()
	defer contx.Done()
	var idStruct ElixirIdentity

	oauth2Token, err := oauth2Config.Exchange(contx, code)
	if err != nil {
		log.Error("Failed to fetch oauth2 code")
		return idStruct, err
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Error("Failed to extract a valid id token from OAuth2 token")
		return idStruct, err
	}

	var verifier = provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

	// Parse and verify ID Token payload.
	_, err = verifier.Verify(contx, rawIDToken)
	if err != nil {
		log.Error("Failed to verify id token")
		return idStruct, err
	}

	// Fetch user information
	userInfo, err := provider.UserInfo(contx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		log.Error("Failed to get userinfo")
		return idStruct, err
	}

	// Extract custom ga4gh_passport_v1 claim
	var claims struct {
		PassportClaim []string `json:"ga4gh_passport_v1"`
	}
	if err := userInfo.Claims(&claims); err != nil {
		log.Error("Failed to get custom ga4gh_passport_v1 claim")
		return idStruct, err
	}

	idStruct = ElixirIdentity{
		User:     removeHost(userInfo.Subject),
		Token:    rawIDToken,
		Passport: claims.PassportClaim,
	}

	return idStruct, err

}

// Returns long-lived token as string
func generateJwtFromElixir(tokenElixir, key, alg string) string {
	var (
		elixirClaims   jwt.MapClaims
		EGAtokenString string
	)

	token, _ := jwt.Parse(tokenElixir, func(tokenElixir *jwt.Token) (interface{}, error) { return nil, nil })
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		elixirClaims = claims
	} else {
		log.Error("Claims in token are empty")
	}

	ttl := 170 * time.Hour
	elixirClaims["exp"] = time.Now().UTC().Add(ttl).Unix()
	EGAtoken := jwt.NewWithClaims(jwt.GetSigningMethod(alg), token.Claims)
	EGAtoken.Header = token.Header
	data, err := ioutil.ReadFile(key)
	if err != nil {
		log.Fatal(err, data)
	}

	switch alg {
	case "ES256":
		pk, err := jwt.ParseECPrivateKeyFromPEM(data)
		if err != nil {
			log.Fatal(err, pk)
		}
		EGAtokenString, err = token.SignedString(pk)
		if err != nil {
			log.Fatal(err, EGAtokenString)
		}
	case "RS256":
		pk, err := jwt.ParseRSAPrivateKeyFromPEM(data)
		if err != nil {
			log.Fatal(err, pk)
		}
		EGAtokenString, err = token.SignedString(pk)
		if err != nil {
			log.Fatal(err, EGAtokenString)
		}
	}

	return EGAtokenString
}
