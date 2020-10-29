package main

import (
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// ElixirConfig stores the config about the elixir oidc endpoint
type ElixirConfig struct {
	id          string
	issuer      string
	redirectURL string
	secret      string
	scope       string
}

// CegaConfig stores information about the cega endpoint
type CegaConfig struct {
	authURL         string
	id              string
	jwtIssuer       string
	jwtPrivateKey   string
	jwtSignatureAlg string
	secret          string
}

// ServerConfig stores general server information
type ServerConfig struct {
	cert string
	key  string
}

// Config is a parent object for all the different configuration parts
type Config struct {
	Elixir  ElixirConfig
	Cega    CegaConfig
	Server  ServerConfig
	S3Inbox string
}

// NewConfig initializes and parses the config file and/or environment using
// the viper library.
func NewConfig() *Config {
	parseConfig()

	c := &Config{}
	c.readConfig()

	return c
}

func (c *Config) readConfig() {
	// Setup elixir
	elixir := ElixirConfig{}

	elixir.id = viper.GetString("elixir.id")
	elixir.issuer = viper.GetString("elixir.issuer")
	elixir.redirectURL = viper.GetString("elixir.redirectUrl")
	elixir.secret = viper.GetString("elixir.secret")
	elixir.scope = viper.GetString("elixir.scope")

	c.Elixir = elixir

	// Setup cega
	cega := CegaConfig{}

	cega.authURL = viper.GetString("cega.authUrl")
	cega.id = viper.GetString("cega.id")
	cega.jwtIssuer = viper.GetString("cega.jwtIssuer")
	cega.jwtPrivateKey = viper.GetString("cega.jwtPrivateKey")
	cega.jwtSignatureAlg = viper.GetString("cega.jwtSignatureAlg")
	cega.secret = viper.GetString("cega.secret")

	c.Cega = cega

	// Setup server
	s := ServerConfig{}

	if viper.IsSet("server.cert") {
		s.cert = viper.GetString("server.cert")
	}
	if viper.IsSet("server.key") {
		s.key = viper.GetString("server.key")
	}

	c.Server = s

	c.S3Inbox = viper.GetString("s3Inbox")

	if viper.IsSet("log.level") {
		stringLevel := viper.GetString("log.level")
		intLevel, err := log.ParseLevel(stringLevel)
		if err != nil {
			log.Printf("Log level '%s' not supported, setting to 'trace'", stringLevel)
			intLevel = log.TraceLevel
		}
		log.SetLevel(intLevel)
		log.Printf("Setting log level to '%s'", stringLevel)
	}
}

func parseConfig() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetConfigType("yaml")
	if viper.IsSet("server.confPath") {
		cp := viper.GetString("server.confPath")
		ss := strings.Split(strings.TrimLeft(cp, "/"), "/")
		viper.AddConfigPath(path.Join(ss...))
	}
	if viper.IsSet("server.confFile") {
		viper.SetConfigFile(viper.GetString("server.confFile"))
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Infoln("No config file found, using ENVs only")
		} else {
			log.Fatalf("Error when reading config file: '%s'", err)
		}
	}
}
