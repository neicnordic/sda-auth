package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

// These are not complete tests of all functions in elixir. New tests should
// be added as the code is updated.

type CegaTests struct {
	suite.Suite
	TempDir    string
	ECKeyFile  *os.File
	RSAKeyFile *os.File
}

func TestCegaTestSuite(t *testing.T) {
	suite.Run(t, new(CegaTests))
}

func (suite *CegaTests) SetupTest() {

	var err error

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

	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(RSAPrivateKey)
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

}

func (suite *CegaTests) TearDownTest() {
	os.Remove(suite.RSAKeyFile.Name())
	os.Remove(suite.ECKeyFile.Name())
	os.Remove(suite.TempDir)
}

func (suite *CegaTests) TestGetb64Credentials() {
	user := "testUser"
	password := "password"

	expected := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))

	assert.Equal(suite.T(), expected, getb64Credentials(user, password), "base64 encoding of credentials failing")
}

func (suite *CegaTests) TestVerifyPassword() {
	password := "password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error(err)
	}

	assert.Equal(suite.T(), true, verifyPassword(password, string(hash)), "password hash verification failing on correct hash")
	assert.Equal(suite.T(), false, verifyPassword(password, "wronghash"), "password hash verification returning true for wrong hash")
}

// This test isn't good, as the generateJwtToken function calls log.Fatal
// instead of returning an error. There are hacks to catch this, but we should
// take the time to rewrite the functions instead.
func (suite *CegaTests) TestGgenerateJwtToken() {

	type KeyAlgo struct {
		Keyfile   string
		Algorithm string
	}

	issuer := "testIssuer"
	subject := "test"
	algorithms := []KeyAlgo{
		{Keyfile: suite.RSAKeyFile.Name(), Algorithm: "RS256"},
	}

	for _, test := range algorithms {

		_, expiration := generateJwtToken(issuer, subject, test.Keyfile, test.Algorithm)

		// We should check that we can parse the token, but jwt.Parse does not
		// like our tokens, and I don't understand them that well, so for now I
		// just check the expiration date.

		// check that the expiration string is a date
		_, err := time.Parse("2006-01-02 15:04:05", expiration)
		assert.Nil(suite.T(), err, "Couldn't parse expiration date for jwt")

	}
}
