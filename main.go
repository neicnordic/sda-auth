package main

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"

	"fmt"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/sessions"
	ulid "github.com/oklog/ulid/v2"
	log "github.com/sirupsen/logrus"
	bcrypt "golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// EGAIdentity represents an EGA user instance
type EGAIdentity struct {
	User  string
	Token string
}

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

// ElixirIdentity represents an Elixir user instance
type ElixirIdentity struct {
	User     string
	Passport []string
	Token    string
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
	token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.StandardClaims{
		ExpiresAt: time.Now().UTC().Add(ttl).Unix(),
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

func main() {
	// Initialise config
	config := NewConfig()

	// Initialise OIDC client
	oauth2Config, provider := getOidcClient(config.Elixir)

	// Initialise web server
	app := iris.New()

	// Start sessions handler in order to send flash messages
	sess := sessions.New(sessions.Config{Cookie: "_session_id", AllowReclaim: true})
	app.Use(sess.Handler())

	app.RegisterView(iris.HTML("./frontend/templates", ".html"))
	app.HandleDir("/public", iris.Dir("./frontend/static"))

	app.Get("/", indexView)

	app.Post("/ega", func(ctx iris.Context) {

		s := sessions.Get(ctx)

		userform := ctx.FormValues()
		username := userform["username"][0]
		password := userform["password"][0]

		client := &http.Client{}
		payload := strings.NewReader("")
		req, err := http.NewRequest("GET", fmt.Sprintf("%s%s?idType=username", config.Cega.authURL, username), payload)

		if err != nil {
			log.Fatal(err)
		}

		req.Header.Add("Authorization", "Basic "+getb64Credentials(config.Cega.id, config.Cega.secret))
		req.Header.Add("Content-Type", "application/json")

		res, err := client.Do(req)

		if err != nil {
			log.Fatal(err)
		}

		defer res.Body.Close()

		if res.StatusCode == 200 {

			if err != nil {
				log.Fatal(err)
			}

			var ur CegaUserResponse
			err = json.NewDecoder(res.Body).Decode(&ur)

			if err != nil {
				log.Error("Failed to parse response: ", err)
				return
			}

			hash := ur.Results.Response[0].PasswordHash

			if verifyPassword(password, hash) == true {
				log.Info("Valid password entered by user: ", username)
				token := generateJwtToken(config.Cega.jwtIssuer, username, config.Cega.jwtPrivateKey, config.Cega.jwtSignatureAlg)
				idStruct := EGAIdentity{User: username, Token: token}
				ctx.View("ega.html", idStruct)

			} else {
				log.Error("Invalid password entered by user: ", username)
				s.SetFlash("message", "Provided credentials are not valid")
				ctx.Redirect("/ega/login", iris.StatusSeeOther)
			}

		} else if res.StatusCode == 404 {
			log.Error("Failed to authenticate user: ", username)
			s.SetFlash("message", "EGA authentication server could not be contacted")
			ctx.Redirect("/ega/login", iris.StatusSeeOther)

		} else {
			log.Error("Failed to authenticate user: ", username)
			s.SetFlash("message", "Provided credentials are not valid")
			ctx.Redirect("/ega/login", iris.StatusSeeOther)
		}
	})

	app.Get("/ega/login", func(ctx iris.Context) {
		s := sessions.Get(ctx)
		message := s.GetFlashString("message")
		log.Info(s.GetFlashes())
		if message == "" {
			ctx.View("loginform.html")
			return
		}
		ctx.View("loginform.html", EGALoginError{Reason: message})
	})

	app.Get("/elixir", func(ctx iris.Context) {
		t := time.Unix(1000000, 0)
		entropy := ulid.Monotonic(rand.New(rand.NewSource(t.UnixNano())), 0)
		state := ulid.MustNew(ulid.Timestamp(t), entropy)
		ctx.Redirect(oauth2Config.AuthCodeURL(state.String()))
	})

	app.Get("/elixir/login", func(ctx iris.Context) {
		contx := context.Background()
		defer contx.Done()
		log.Info(ctx.Request().Body)

		oauth2Token, err := oauth2Config.Exchange(contx, ctx.Request().URL.Query().Get("code"))
		if err != nil {
			log.Error("Failed to fetch oauth2 code")
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Error("Failed to extract a valid id token from OAuth2 token")
			return
		}

		var verifier = provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

		// Parse and verify ID Token payload.
		_, err = verifier.Verify(contx, rawIDToken)
		if err != nil {
			log.Error("Failed to verify id token")
			return
		}

		// Fetch user information
		userInfo, err := provider.UserInfo(contx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			log.Error("Failed to get userinfo")
			return
		}

		// Extract custom ga4gh_passport_v1 claim
		var claims struct {
			PassportClaim []string `json:"ga4gh_passport_v1"`
		}
		if err := userInfo.Claims(&claims); err != nil {
			log.Error("Failed to get custom ga4gh_passport_v1 claim")
			return
		}

		idStruct := ElixirIdentity{User: userInfo.Subject, Token: rawIDToken, Passport: claims.PassportClaim}

		log.Infoln("User was authenticated: ", userInfo.Subject)
		ctx.View("elixir.html", idStruct)
	})

	if config.Server.cert != "" && config.Server.key != "" {

		log.Infoln("Serving content using https")
		app.Run(iris.TLS("0.0.0.0:8080", config.Server.cert, config.Server.key))

	} else {

		log.Infoln("Serving content using http")
		server := &http.Server{Addr: "0.0.0.0:8080"}
		app.Run(iris.Server(server))

	}
}

func indexView(ctx iris.Context) {
	ctx.View("index.html")
}
