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
		ctx.View("index.html")
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

			ok := verifyPassword(password, hash)

			if ok == true {
				log.Info("Valid password entered by user: ", username)
				token := generateJwtToken(config.Cega.jwtIssuer, username, config.Cega.jwtPrivateKey, config.Cega.jwtSignatureAlg)
				s3conf := getS3ConfigMap(token, config.S3Inbox, username)
				idStruct := EGAIdentity{User: username, Token: token}
				s.SetFlash("s3conf", s3conf)
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

	app.Get("/ega/s3conf", func(ctx iris.Context) {
		s := sessions.Get(ctx)
		s3conf := s.GetFlash("s3conf")
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

		io.Copy(ctx.ResponseWriter(), strings.NewReader(s3c))
	})

	app.Get("/ega/login", func(ctx iris.Context) {
		s := sessions.Get(ctx)
		message := s.GetFlashString("message")
		if message == "" {
			ctx.View("loginform.html")
			return
		}
		ctx.View("loginform.html", EGALoginError{Reason: message})
	})

	app.Get("/elixir", func(ctx iris.Context) {
		state := uuid.New()
		ctx.SetCookie(&http.Cookie{Name: "state", Value: state.String(), Secure: true})
		ctx.Redirect(oauth2Config.AuthCodeURL(state.String()))
	})

	app.Get("/elixir/login", func(ctx iris.Context) {
		state := ctx.Request().URL.Query().Get("state")
		sessionState := ctx.GetCookie("state")

		if state != sessionState {
			log.Errorf("State of incoming request (%s) does not match with your session's state (%s)", state)
			ctx.Writef("Authentication failed. You may need to clear your session cookies and try again.")
			return
		}

		code := ctx.Request().URL.Query().Get("code")
		idStruct, err := authenticateWithOidc(oauth2Config, provider, code)

		if err != nil {
			log.Error(err)
			ctx.Writef("Authentication failed. You may need to clear your session cookies and try again.")
			return
		}
		log.Infof("User was authenticated: %s", idStruct.User)
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
