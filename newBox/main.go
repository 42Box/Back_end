package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/pat"
	"github.com/gorilla/sessions"
	"github.com/urfave/negroni"
	"golang.org/x/oauth2"
)

var ftOauthConfig = oauth2.Config{
	RedirectURL:  "http://localhost:3000/auth/42/callback",
	ClientID:     "u-s4t2ud-91c7e66e631116ce10a695cce66d26e87d6afe6bcc4bc93dca5d3408292f427f",
	ClientSecret: "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",
	Endpoint: oauth2.Endpoint{
		AuthURL:  "https://api.intra.42.fr/oauth/authorize",
		TokenURL: "https://api.intra.42.fr/oauth/token",
	},
}

var store = sessions.NewCookieStore([]byte("my-secret-key"))

func ftLoginHandler(w http.ResponseWriter, r *http.Request) {
	state := generateStateOauthCookie(w)
	url := ftOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	expiration := time.Now().Add(1 * 24 * time.Hour)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := &http.Cookie{Name: "oauthstate", Value: state, Expires: expiration, HttpOnly: true}
	http.SetCookie(w, cookie)
	return state
}

var TokenList map[string]interface{}

func ftGetToken(w http.ResponseWriter, r *http.Request) (*oauth2.Token, error) {
	oauthstate, err := r.Cookie("oauthstate")
	if r.FormValue("state") != oauthstate.Value {
		log.Printf("invalid 42 oauth state cookie: %s state %s\n", oauthstate.Value, r.FormValue("state"))
		http.Redirect(w, r, "/error", http.StatusTemporaryRedirect)
		return nil, fmt.Errorf("oauthstate Cookie is wrong")
	}
	token, err := ftOauthConfig.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		return nil, fmt.Errorf("Failed to Exchange %s\n", err.Error())
	}
	return token, nil
}

func isHaveToken(w http.ResponseWriter, r *http.Request) (*oauth2.Token, error) {
	session, err := store.Get(r, "my-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, fmt.Errorf("Failed to session")
	}
	token, err := ftGetToken(w, r)
	if err != nil {
		return nil, err
	}
	session.Values["token"] = token
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, fmt.Errorf("Failed to save session")
	}
	return token, nil
}

func ftGetWhoAmI(w http.ResponseWriter, r *http.Request, access string) ([]byte, error) {
	req, err := http.NewRequest("GET", "https://api.intra.42.fr/v2/me", nil)
	if err != nil {
		return nil, fmt.Errorf("request to v2/me failed\n")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", access))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Get method is Wrong\n")
	}
	data, err := ioutil.ReadAll(resp.Body)
	return data, err
}

func ftGetTokensHandler(w http.ResponseWriter, r *http.Request) {
	oauthstate, err := r.Cookie("oauthstate")
	if r.FormValue("state") != oauthstate.Value {
		log.Printf("invalid 42 oauth state cookie: %s state %s\n", oauthstate.Value, r.FormValue("state"))
		http.Redirect(w, r, "/error", http.StatusTemporaryRedirect)
		return
	}
	token, err := ftOauthConfig.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		return
	}
	session, err := store.Get(r, "my-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["42box"] = token
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func ftGivemeHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "my-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token := session.Values["42box"].(*oauth2.Token)
	println(token)
	data, err := ftGetWhoAmI(w, r, token.AccessToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, data)
}
func ftErrorHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Something wrong")
}
func main() {
	mux := pat.New()
	mux.HandleFunc("/", ftLoginHandler)
	mux.HandleFunc("/error", ftErrorHandler)
	mux.HandleFunc("/auth/42/callback", ftGetTokensHandler)
	mux.HandleFunc("/42box/me", ftGivemeHandler)
	n := negroni.Classic()
	n.UseHandler(mux)

	http.ListenAndServe(":3000", n)
}
