package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/oauth2-proxy/mockoidc"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

type ElixirTests struct {
	suite.Suite
	TempDir      string
	ECKeyFile    *os.File
	RSAKeyFile   *os.File
	mockServer   *mockoidc.MockOIDC
	ElixirConfig ElixirConfig
}

func TestElixirTestSuite(t *testing.T) {
	suite.Run(t, new(ElixirTests))
}

func (suite *ElixirTests) SetupTest() {

	var err error

	suite.mockServer, err = mockoidc.Run()
	if err != nil {
		log.Error(err)
	}

	// Create a temporary directory for our config file
	suite.TempDir, err = ioutil.TempDir(os.TempDir(), "sda-auth-test-")
	if err != nil {
		log.Fatal("Couldn't create temporary test directory", err)
	}

	// Create RSA private key file
	suite.RSAKeyFile, err = ioutil.TempFile(suite.TempDir, "rsakey-")
	if err != nil {
		log.Fatal("Cannot create temporary rsa key file", err)
	}

	RSAPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Error("Failed to generate RSA key")
	}

	var privateKeyBytes = x509.MarshalPKCS1PrivateKey(RSAPrivateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	err = pem.Encode(suite.RSAKeyFile, privateKeyBlock)
	if err != nil {
		log.Error("Error writing RSA private key")
	}

	// Create EC private key file
	suite.ECKeyFile, err = ioutil.TempFile(suite.TempDir, "eckey-")
	if err != nil {
		log.Fatal("Cannot create temporary ec key file", err)
	}

	ECPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Error("Failed to generate EC key")
	}

	privateKeyBytes, err = x509.MarshalECPrivateKey(ECPrivateKey)
	if err != nil {
		log.Error("Failed to marshal EC key")
	}
	privateKeyBlock = &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	err = pem.Encode(suite.ECKeyFile, privateKeyBlock)
	if err != nil {
		log.Error("Error writing EC private key")
	}

	// create an elixir config that has the needed endpoints set
	suite.ElixirConfig = ElixirConfig{
		ID:              suite.mockServer.ClientID,
		Issuer:          suite.mockServer.Issuer(),
		RedirectURL:     "http://redirect",
		Secret:          suite.mockServer.ClientSecret,
		JwtPrivateKey:   "testPrivateKey",
		JwtSignatureAlg: "testAlg",
	}
}

func (suite *ElixirTests) TearDownTest() {
	err := suite.mockServer.Shutdown()
	if err != nil {
		log.Errorf("Couldn't shut down mock OIDC server: %v", err)
	}
}

func (suite *ElixirTests) TestGetOidcClient() {

	expectedEndpoint := oauth2.Endpoint{
		AuthURL:   suite.mockServer.AuthorizationEndpoint(),
		TokenURL:  suite.mockServer.TokenEndpoint(),
		AuthStyle: 0}

	oauth2Config, provider := getOidcClient(suite.ElixirConfig)
	assert.Equal(suite.T(), suite.mockServer.ClientID, oauth2Config.ClientID, "ClientID was modified when creating the oauth2Config")
	assert.Equal(suite.T(), suite.mockServer.ClientSecret, oauth2Config.ClientSecret, "ClientSecret was modified when creating the oauth2Config")
	assert.Equal(suite.T(), suite.ElixirConfig.RedirectURL, oauth2Config.RedirectURL, "RedirectURL was modified when creating the oauth2Config")
	assert.Equal(suite.T(), expectedEndpoint, oauth2Config.Endpoint, "Issuer was modified when creating the oauth2Config")
	assert.Equal(suite.T(), expectedEndpoint, provider.Endpoint(), "provider has the wrong endpoint")
	assert.Equal(suite.T(), []string{"openid", "ga4gh_passport_v1 profile email"}, oauth2Config.Scopes, "oauth2Config has the wrong scopes")
}

func (suite *ElixirTests) TestRemoveHost() {
	assert.Equal(suite.T(), "test1", removeHost("test1"), "removeHost should return the input string when given 'test1'")
	assert.Equal(suite.T(), "test2", removeHost("test2@test.com"), "removeHost should return 'test2' when given 'test2@test.com'")
	assert.Equal(suite.T(), "test3", removeHost("test3@test@test.com"), "removeHost should return 'test3' when given 'test3@test@test.com'")
}

func (suite *ElixirTests) TestAuthenticateWithOidc() {

	// Create a code to authenticate

	session, err := suite.mockServer.SessionStore.NewSession(
		"openid email profile", "nonce", mockoidc.DefaultUser(), "", "")
	if err != nil {
		log.Error(err)
	}
	code := session.SessionID

	oauth2Config, provider := getOidcClient(suite.ElixirConfig)

	elixirIdentity, err := authenticateWithOidc(oauth2Config, provider, code)
	assert.Nil(suite.T(), err, "Failed to authenticate with OIDC")
	assert.NotEqual(suite.T(), "", elixirIdentity.Token, "Empty token returned from OIDC authentication")
}

func (suite *ElixirTests) TestGenerateJwtFromElixirRSA() {
	var (
		EGAclaims jwt.MapClaims
		JWTRSAalg = "RS256"
	)

	session, err := suite.mockServer.SessionStore.NewSession("openid email profile", "nonce", mockoidc.DefaultUser(), "", "")
	if err != nil {
		log.Error(err)
	}
	oauth2Config, provider := getOidcClient(suite.ElixirConfig)
	elixirIdentity, err := authenticateWithOidc(oauth2Config, provider, session.SessionID)
	elixirJWT := elixirIdentity.Token

	idStruct := ElixirIdentity{
		User:     "",
		Token:    elixirJWT,
		Passport: nil,
		Profile:  "Dummy Tester",
		Email:    "dummy.tester@gs.uu.se",
	}
	tokenEGA, _, err := generateJwtFromElixir(idStruct, suite.RSAKeyFile.Name(), JWTRSAalg, "http://test.login.org/elixir/login", suite.mockServer.JWKSEndpoint())
	assert.Nil(suite.T(), err)
	token, _ := jwt.Parse(tokenEGA, func(tokenEGA *jwt.Token) (interface{}, error) { return nil, nil })
	EGAclaims, ok := token.Claims.(jwt.MapClaims)
	assert.True(suite.T(), ok)

	expDateStr := fmt.Sprintf("%.0f", EGAclaims["exp"])
	expDateInt, err := strconv.ParseInt(expDateStr, 10, 64)
	assert.Nil(suite.T(), err)

	assert.Equal(suite.T(), expDateInt, time.Now().Add(170*time.Hour).Unix())

	assert.Equal(suite.T(), idStruct.Profile, EGAclaims["name"])

	assert.Equal(suite.T(), idStruct.Email, EGAclaims["email"])

	defer os.Remove("keys/sign-rsa-jwt.key")
}

func (suite *ElixirTests) TestGenerateJwtFromElixirEC() {
	var (
		EGAclaims jwt.MapClaims
		JWTalg    = "ES256"
	)

	session, err := suite.mockServer.SessionStore.NewSession("openid email profile", "nonce", mockoidc.DefaultUser(), "", "")
	if err != nil {
		log.Error(err)
	}
	oauth2Config, provider := getOidcClient(suite.ElixirConfig)
	elixirIdentity, err := authenticateWithOidc(oauth2Config, provider, session.SessionID)
	elixirJWT := elixirIdentity.Token

	idStruct := ElixirIdentity{
		User:     "",
		Token:    elixirJWT,
		Passport: nil,
		Profile:  "Dummy Tester",
		Email:    "dummy.tester@gs.uu.se",
	}
	tokenEGA, _, err := generateJwtFromElixir(idStruct, suite.ECKeyFile.Name(), JWTalg, "http://test.login.org/elixir/login", suite.mockServer.JWKSEndpoint())
	assert.Nil(suite.T(), err)

	token, _ := jwt.Parse(tokenEGA, func(tokenEGA *jwt.Token) (interface{}, error) { return nil, nil })
	EGAclaims, ok := token.Claims.(jwt.MapClaims)
	assert.True(suite.T(), ok)

	expDateStr := fmt.Sprintf("%.0f", EGAclaims["exp"])
	expDateInt, err := strconv.ParseInt(expDateStr, 10, 64)
	assert.Nil(suite.T(), err)

	assert.Equal(suite.T(), expDateInt, time.Now().Add(170*time.Hour).Unix())

	assert.Equal(suite.T(), idStruct.Profile, EGAclaims["name"])

	assert.Equal(suite.T(), idStruct.Email, EGAclaims["email"])

	defer os.Remove("keys/sign-ecdsa-jwt.key")
}

func (suite *ElixirTests) TestValidateJwt() {
	session, err := suite.mockServer.SessionStore.NewSession("openid email profile", "nonce", mockoidc.DefaultUser(), "", "")
	if err != nil {
		log.Error(err)
	}
	oauth2Config, provider := getOidcClient(suite.ElixirConfig)
	elixirIdentity, err := authenticateWithOidc(oauth2Config, provider, session.SessionID)
	elixirJWT := elixirIdentity.Token

	// Create HS256 test token
	mySigningKey := []byte("AllYourBase")
	claims := &jwt.StandardClaims{
		Issuer: "test",
	}
	tokenHS256 := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	testTokenHS256, err := tokenHS256.SignedString(mySigningKey)
	if err != nil {
		log.Error(err)
	}

	// Create RSA test token
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Error(err)
	}
	tokenRSA := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	testTokenRSA, err := tokenRSA.SignedString(rsaKey)
	if err != nil {
		log.Error(err)
	}

	// Create RSA test token
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Error(err)
	}
	tokenEC := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	testTokenEC, err := tokenEC.SignedString(ecKey)
	if err != nil {
		log.Error(err)
	}

	// sanity check
	token, err := validateToken(elixirJWT, suite.mockServer.JWKSEndpoint())
	if assert.Nil(suite.T(), err) {
		assert.True(suite.T(), token.Valid, "Validation failed but without returning errors")
	}

	// wrong jwk url
	token, err = validateToken(elixirJWT, "http://some/jwk/endpoint")
	assert.ErrorContains(suite.T(), err, "failed to fetch remote JWK")

	// wrong signing method
	_, err = validateToken(testTokenHS256, suite.mockServer.JWKSEndpoint())
	if assert.Error(suite.T(), err) {
		assert.Equal(suite.T(), "unexpected signing method", err.Error())
	}

	// wrong private key, RSA
	_, err = validateToken(testTokenRSA, suite.mockServer.JWKSEndpoint())
	if assert.Error(suite.T(), err) {
		assert.Equal(suite.T(), "signature not valid: crypto/rsa: verification error", err.Error())
	}

	// wrong private key, ECDSA
	_, err = validateToken(testTokenEC, suite.mockServer.JWKSEndpoint())
	if assert.Error(suite.T(), err) {
		assert.Equal(suite.T(), "signature not valid: key is of invalid type", err.Error())
	}
}
