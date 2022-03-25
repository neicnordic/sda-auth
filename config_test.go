package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

// These are not complete tests of all functions in elixir. New tests should
// be added as the code is updated.

type ConfigTests struct {
	suite.Suite
	TempDir      string
	ConfigFile   *os.File
	ElixirConfig ElixirConfig
	CegaConfig   CegaConfig
	ServerConfig ServerConfig
	S3Inbox      string
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ConfigTests))
}

func (suite *ConfigTests) SetupTest() {

	var err error

	// config values to write to the config file
	suite.ElixirConfig = ElixirConfig{
		ID:              "elixirTestID",
		Issuer:          "elixirTestIssuer",
		RedirectURL:     "http://elixir/login",
		RevocationURL:   "http://elixir/revoke",
		Secret:          "elixirTestSecret",
		JwtPrivateKey:   "elixirKey.file",
		JwtSignatureAlg: "elixirSigAlg",
	}

	suite.CegaConfig = CegaConfig{
		AuthURL:         "http://cega/auth",
		ID:              "cegaID",
		JwtIssuer:       "cegaJwtIssuer",
		JwtPrivateKey:   "cegaJwtPrivateKey",
		JwtSignatureAlg: "cegaSigAlg",
		Secret:          "cegaSecret",
	}

	suite.ServerConfig = ServerConfig{
		Cert: "serverCert.pem",
		Key:  "serverKey.pem",
	}

	// Create a temporary directory for our config file
	suite.TempDir, err = ioutil.TempDir(os.TempDir(), "sda-auth-test-")
	if err != nil {
		log.Fatal("Couldn't create temporary test directory", err)
	}
	suite.ConfigFile, err = os.Create(filepath.Join(suite.TempDir, "config.yaml"))
	if err != nil {
		log.Fatal("Cannot create temporary public key file", err)
	}
	suite.S3Inbox = "s3://testInbox"

	// Write config to temp config file
	configYaml, err := yaml.Marshal(Config{
		Elixir:  suite.ElixirConfig,
		Cega:    suite.CegaConfig,
		Server:  suite.ServerConfig,
		S3Inbox: suite.S3Inbox,
	})
	if err != nil {
		log.Errorf("Error marshalling config yaml: %v", err)
	}
	_, err = suite.ConfigFile.Write(configYaml)
	if err != nil {
		log.Errorf("Error writing config file: %v", err)
	}

}

func (suite *ConfigTests) TearDownTest() {
	os.Remove(suite.ConfigFile.Name())
	os.Remove(suite.TempDir)
}

// Both readConfig and parseConfig is called when using NewConfig, so they are
// both tested in this single test.
func (suite *ConfigTests) TestConfig() {

	// change dir so that we read the right config
	err := os.Chdir(suite.TempDir)
	if err != nil {
		log.Errorf("Couldn't access temp directory: %v", err)
	}

	config := NewConfig()

	// Check elixir values
	assert.Equal(suite.T(), suite.ElixirConfig.ID, config.Elixir.ID, "Elixir ID misread from config file")
	assert.Equal(suite.T(), suite.ElixirConfig.Issuer, config.Elixir.Issuer, "Elixir Issuer misread from config file")
	assert.Equal(suite.T(), suite.ElixirConfig.RedirectURL, config.Elixir.RedirectURL, "Elixir RedirectURL misread from config file")
	assert.Equal(suite.T(), suite.ElixirConfig.Secret, config.Elixir.Secret, "Elixir Secret misread from config file")
	assert.Equal(suite.T(), suite.ElixirConfig.JwtPrivateKey, config.Elixir.JwtPrivateKey, "Elixir JwtPrivateKey misread from config file")
	assert.Equal(suite.T(), suite.ElixirConfig.JwtSignatureAlg, config.Elixir.JwtSignatureAlg, "Elixir JwtSignatureAlg misread from config file")

	// Check CEGA values
	assert.Equal(suite.T(), suite.CegaConfig.ID, config.Cega.ID, "CEGA ID misread from config file")
	assert.Equal(suite.T(), suite.CegaConfig.AuthURL, config.Cega.AuthURL, "CEGA AuthURL misread from config file")
	assert.Equal(suite.T(), suite.CegaConfig.JwtIssuer, config.Cega.JwtIssuer, "CEGA JwtIssuer misread from config file")
	assert.Equal(suite.T(), suite.CegaConfig.JwtPrivateKey, config.Cega.JwtPrivateKey, "CEGA JwtPrivateKey misread from config file")
	assert.Equal(suite.T(), suite.CegaConfig.JwtSignatureAlg, config.Cega.JwtSignatureAlg, "CEGA JwtSignatureAlg misread from config file")
	assert.Equal(suite.T(), suite.CegaConfig.Secret, config.Cega.Secret, "CEGA Secret misread from config file")

	// Check ServerConfig values
	assert.Equal(suite.T(), suite.ServerConfig.Cert, config.Server.Cert, "ServerConfig Cert misread from config file")
	assert.Equal(suite.T(), suite.ServerConfig.Key, config.Server.Key, "ServerConfig Key misread from config file")

	// Check S3Inbox value
	assert.Equal(suite.T(), suite.S3Inbox, config.S3Inbox, "S3Inbox misread from config file")

	// Set all values as environment variables
	os.Setenv("ELIXIR_ID", fmt.Sprintf("env_%v", suite.ElixirConfig.ID))
	os.Setenv("ELIXIR_ISSUER", fmt.Sprintf("env_%v", suite.ElixirConfig.Issuer))
	os.Setenv("ELIXIR_REDIRECTURL", fmt.Sprintf("env_%v", suite.ElixirConfig.RedirectURL))
	os.Setenv("ELIXIR_SECRET", fmt.Sprintf("env_%v", suite.ElixirConfig.Secret))
	os.Setenv("ELIXIR_JWTPRIVATEKEY", fmt.Sprintf("env_%v", suite.ElixirConfig.JwtPrivateKey))
	os.Setenv("ELIXIR_JWTSIGNATUREALG", fmt.Sprintf("env_%v", suite.ElixirConfig.JwtSignatureAlg))

	os.Setenv("CEGA_ID", fmt.Sprintf("env_%v", suite.CegaConfig.ID))
	os.Setenv("CEGA_AUTHURL", fmt.Sprintf("env_%v", suite.CegaConfig.AuthURL))
	os.Setenv("CEGA_JWTISSUER", fmt.Sprintf("env_%v", suite.CegaConfig.JwtIssuer))
	os.Setenv("CEGA_JWTPRIVATEKEY", fmt.Sprintf("env_%v", suite.CegaConfig.JwtPrivateKey))
	os.Setenv("CEGA_JWTSIGNATUREALG", fmt.Sprintf("env_%v", suite.CegaConfig.JwtSignatureAlg))
	os.Setenv("CEGA_SECRET", fmt.Sprintf("env_%v", suite.CegaConfig.Secret))

	os.Setenv("SERVER_CERT", fmt.Sprintf("env_%v", suite.ServerConfig.Cert))
	os.Setenv("SERVER_KEY", fmt.Sprintf("env_%v", suite.ServerConfig.Key))

	os.Setenv("S3INBOX", fmt.Sprintf("env_%v", suite.S3Inbox))

	// re-read the config
	config = NewConfig()

	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.ElixirConfig.ID), config.Elixir.ID, "Elixir ID misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.ElixirConfig.Issuer), config.Elixir.Issuer, "Elixir Issuer misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.ElixirConfig.RedirectURL), config.Elixir.RedirectURL, "Elixir RedirectURL misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.ElixirConfig.Secret), config.Elixir.Secret, "Elixir Secret misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.ElixirConfig.JwtPrivateKey), config.Elixir.JwtPrivateKey, "Elixir JwtPrivateKey misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.ElixirConfig.JwtSignatureAlg), config.Elixir.JwtSignatureAlg, "Elixir JwtSignatureAlg misread from environment variable")

	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.CegaConfig.ID), config.Cega.ID, "CEGA ID misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.CegaConfig.AuthURL), config.Cega.AuthURL, "CEGA AuthURL misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.CegaConfig.JwtIssuer), config.Cega.JwtIssuer, "CEGA JwtIssuer misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.CegaConfig.JwtPrivateKey), config.Cega.JwtPrivateKey, "CEGA JwtPrivateKey misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.CegaConfig.JwtSignatureAlg), config.Cega.JwtSignatureAlg, "CEGA JwtSignatureAlg misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.CegaConfig.Secret), config.Cega.Secret, "CEGA Secret misread from environment variable")

	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.ServerConfig.Cert), config.Server.Cert, "ServerConfig Cert misread from environment variable")
	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.ServerConfig.Key), config.Server.Key, "ServerConfig Key misread from environment variable")

	assert.Equal(suite.T(), fmt.Sprintf("env_%v", suite.S3Inbox), config.S3Inbox, "S3Inbox misread from environment variable")

}