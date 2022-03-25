package main

import (
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// ElixirConfig stores the config about the elixir oidc endpoint
type ElixirConfig struct {
	ID              string
	Issuer          string
	RedirectURL     string
	RevocationURL   string
	Secret          string
	JwtPrivateKey   string
	JwtSignatureAlg string
}

// CegaConfig stores information about the cega endpoint
type CegaConfig struct {
	AuthURL         string
	ID              string
	JwtIssuer       string
	JwtPrivateKey   string
	JwtSignatureAlg string
	Secret          string
}

// ServerConfig stores general server information
type ServerConfig struct {
	Cert string
	Key  string
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

	elixir.ID = viper.GetString("elixir.id")
	elixir.Issuer = viper.GetString("elixir.issuer")
	elixir.RedirectURL = viper.GetString("elixir.redirectUrl")
	elixir.Secret = viper.GetString("elixir.secret")
	elixir.JwtPrivateKey = viper.GetString("elixir.jwtPrivateKey")
	elixir.JwtSignatureAlg = viper.GetString("elixir.jwtSignatureAlg")

	c.Elixir = elixir

	// Setup cega
	cega := CegaConfig{}

	cega.AuthURL = viper.GetString("cega.authUrl")
	cega.ID = viper.GetString("cega.id")
	cega.JwtIssuer = viper.GetString("cega.jwtIssuer")
	cega.JwtPrivateKey = viper.GetString("cega.jwtPrivateKey")
	cega.JwtSignatureAlg = viper.GetString("cega.jwtSignatureAlg")
	cega.Secret = viper.GetString("cega.secret")

	c.Cega = cega

	// Setup server
	s := ServerConfig{}

	if viper.IsSet("server.cert") {
		s.Cert = viper.GetString("server.cert")
	}
	if viper.IsSet("server.key") {
		s.Key = viper.GetString("server.key")
	}

	c.Server = s

	c.S3Inbox = viper.GetString("s3Inbox")

	if viper.IsSet("log.format") {
		if viper.GetString("log.format") == "json" {
			log.SetFormatter(&log.JSONFormatter{})
			log.Info("The logs format is set to JSON")
		}
	}

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
