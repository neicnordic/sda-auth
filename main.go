package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/sessions"
	log "github.com/sirupsen/logrus"
)

type LoginOption struct {
	Name string
	URL  string
}

func getInboxConfig(ctx iris.Context, authType string) {
	s := sessions.Get(ctx)
	s3conf := s.GetFlash(authType)
	if s3conf == nil {
		ctx.Redirect("/")
		return
	}
	s3cfmap := s3conf.(map[string]string)
	ctx.ResponseWriter().Header().Set("Content-Disposition", "attachment; filename=s3cmd.conf")
	var s3c string

	for k, v := range s3cfmap {
		entry := fmt.Sprintf("%s = %s\n", k, v)
		s3c = s3c + entry
	}

	_, err := io.Copy(ctx.ResponseWriter(), strings.NewReader(s3c))
	if err != nil {
		log.Error("Failed to write s3config response: ", err)
		return
	}

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

	app.Get("/", func(ctx iris.Context) {
		err := ctx.View("index.html")
		if err != nil {
			log.Error("Failed to view index page: ", err)
			return
		}
	})

	app.Post("/ega", func(ctx iris.Context) {

		s := sessions.Get(ctx)

		userform := ctx.FormValues()
		username := userform["username"][0]
		password := userform["password"][0]

		res, err := authenticateWithCEGA(config.Cega, username)

		if err != nil {
			log.Error(err)
		}

		defer res.Body.Close()

		switch res.StatusCode {
		case 200:
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

			ok := verifyPassword(password, hash)

			if ok {
				log.WithFields(log.Fields{"authType": "cega", "user": username}).Info("Valid password entered by user")
				token := generateJwtToken(config.Cega.jwtIssuer, username, config.Cega.jwtPrivateKey, config.Cega.jwtSignatureAlg)
				s3conf := getS3ConfigMap(token, config.S3Inbox, username)
				idStruct := EGAIdentity{User: username, Token: token}
				s.SetFlash("ega", s3conf)
				err := ctx.View("ega.html", idStruct)
				if err != nil {
					log.Error("Failed to parse response: ", err)
					return
				}

			} else {
				log.WithFields(log.Fields{"authType": "cega", "user": username}).Error("Invalid password entered by user")
				s.SetFlash("message", "Provided credentials are not valid")
				ctx.Redirect("/ega/login", iris.StatusSeeOther)
			}

		case 404:
			log.WithFields(log.Fields{"authType": "cega", "user": username}).Error("Failed to authenticate user")
			s.SetFlash("message", "EGA authentication server could not be contacted")
			ctx.Redirect("/ega/login", iris.StatusSeeOther)

		default:
			log.WithFields(log.Fields{"authType": "cega", "user": username}).Error("Failed to authenticate user")
			s.SetFlash("message", "Provided credentials are not valid")
			ctx.Redirect("/ega/login", iris.StatusSeeOther)
		}
	})

	app.Get("/ega/s3conf", func(ctx iris.Context) {
		getInboxConfig(ctx, "ega")
	})

	app.Get("/ega/login", func(ctx iris.Context) {
		s := sessions.Get(ctx)
		message := s.GetFlashString("message")
		if message == "" {
			err := ctx.View("loginform.html")
			if err != nil {
				log.Error("Failed to return to login form: ", err)
				return
			}
			return
		}
		err := ctx.View("loginform.html", EGALoginError{Reason: message})
		if err != nil {
			log.Error("Failed to view invalid credentials form: ", err)
			return
		}
	})

	app.Get("/login-options", func(ctx iris.Context) {
		// Elixir is always available
		response := []LoginOption{{Name: "Elixir", URL: "/elixir"}}
		// Only add the CEGA option if it has both id and secret
		if config.Cega.id != "" && config.Cega.secret != "" {
			response = append(response, LoginOption{Name: "EGA", URL: "/ega/login"})
		}
		ctx.JSON(response)
	})

	app.Get("/elixir", func(ctx iris.Context) {
		state := uuid.New()
		ctx.SetCookie(&http.Cookie{Name: "state", Value: state.String(), Secure: true})
		ctx.Redirect(oauth2Config.AuthCodeURL(state.String()))
	})

	app.Get("/elixir/s3conf", func(ctx iris.Context) {
		getInboxConfig(ctx, "elixir")
	})

	app.Get("/elixir/login", func(ctx iris.Context) {
		state := ctx.Request().URL.Query().Get("state")
		sessionState := ctx.GetCookie("state")

		if state != sessionState {
			log.Errorf("State of incoming request (%s) does not match with your session's state (%s)", state, sessionState)
			_, err := ctx.Writef("Authentication failed. You may need to clear your session cookies and try again.")
			if err != nil {
				log.Error("Failed to write response: ", err)
				return
			}
			return
		}

		code := ctx.Request().URL.Query().Get("code")
		idStruct, err := authenticateWithOidc(oauth2Config, provider, code)

		if err != nil {
			log.WithFields(log.Fields{"authType": "elixir"}).Errorf("Auhentication failed: %s", err)
			_, err := ctx.Writef("Authentication failed. You may need to clear your session cookies and try again.")
			if err != nil {
				log.Error("Failed to write response: ", err)
				return
			}
			return
		}
		log.WithFields(log.Fields{"authType": "elixir", "user": idStruct.User}).Infof("User was authenticated")
		s3conf := getS3ConfigMap(idStruct.Token, config.S3Inbox, idStruct.User)
		s := sessions.Get(ctx)
		s.SetFlash("elixir", s3conf)
		err = ctx.View("elixir.html", idStruct)
		if err != nil {
			log.Error("Failed to view login form: ", err)
			return
		}
	})

	if config.Server.cert != "" && config.Server.key != "" {

		log.Infoln("Serving content using https")
		err := app.Run(iris.TLS("0.0.0.0:8080", config.Server.cert, config.Server.key))
		if err != nil {
			log.Error("Failed to start server:", err)
			return
		}
	} else {

		log.Infoln("Serving content using http")
		server := &http.Server{Addr: "0.0.0.0:8080"}
		err := app.Run(iris.Server(server))
		if err != nil {
			log.Error("Failed to start server:", err)
			return
		}
	}
}
