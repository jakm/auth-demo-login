package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
	"github.com/segmentio/ksuid"
	// "github.com/ory/hydra/rand/sequence"
)

const halfYear = 6 * 30 * 24 * 3600

var (
	config      = Config{}
	redisClient *redis.Client
)

type LoginStatusRes struct {
	Skip    bool   `json:"skip"`
	Subject string `json:"subject"`
}

type LoginAcceptReq struct {
	Subject     string `json:"subject"`
	Remember    bool   `json:"remember"`
	RememberFor uint32 `json:"remember_for"`
}

type RedirectRes struct {
	RedirectTo string `json:"redirect_to"`
}

type RejectReq struct {
	Error      string `json:"error"`
	ErrorDescr string `json:"error_description"`
}

type ConsentStatusRes struct {
	Skip    bool   `json:"skip"`
	Subject string `json:"subject"`
	Client  struct {
		ID   string `json:"client_id"`
		Name string `json:"client_name"`
	} `json:"client"`
	RequestedScope []string `json:"requested_scope"`
}

type ConsentAcceptReq struct {
	GrantScope  []string `json:"grant_scope"`
	Remember    bool     `json:"remember"`
	RememberFor uint32   `json:"remember_for"`
	Session     struct {
		AccessToken map[string]interface{} `json:"access_token"`
		IDToken     map[string]interface{} `json:"id_token"`
	} `json:"session"`
}

type LoginContext struct {
	Challenge string `json:"challenge"`
	Email     string `json:"email"`
	Subject   string `json:"subject"`
}

func init() {
	err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%+v", config)

	redisClient = redis.NewClient(&redis.Options{
		Addr:     config.Redis.Addr,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	_, err = redisClient.Ping().Result()
	if err != nil {
		log.Fatalf("Redis connection failed: %s", err)
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func main() {
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/consent", consentHandler)
	router.HandleFunc("/confirmMail/{id}", confirmMailHandler)
	router.HandleFunc("/callback", callbackHandler)

	http.ListenAndServeTLS(config.ListenAddr, "cert/server.crt", "cert/server.key", router)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			badRequestError(w, fmt.Errorf("Form parsing failed: %s", err))
			return
		}
		email := r.Form.Get("email")
		challenge := r.Form.Get("challenge")
		if email == "" || challenge == "" {
			badRequestError(w, fmt.Errorf("Missing email or challenge in form data"))
			return
		}

		subject, err := makeSubject(email)
		if err != nil {
			internalError(w, fmt.Errorf("Error getting subject for email %s: %s", email, err))
			return
		}

		sendConfirmEmail(w, r, email, challenge, subject)
		return
	}

	challenge := r.URL.Query().Get("login_challenge")
	if challenge == "" {
		badRequestError(w, fmt.Errorf("Missing challenge argument: %s", r.URL.String()))
		return
	}

	v, err := getLoginStatus(challenge)
	if err != nil {
		internalError(w, err)
		return
	}
	if v.Skip {
		// XXX: verify login status in db
		acceptLogin(w, r, challenge, v.Subject, v.Skip)
		// rejectLogin(w, r, challenge, v.Subject)
		return
	}

	showLoginForm(w, r, challenge)
}

func consentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			badRequestError(w, fmt.Errorf("Form parsing failed: %s", err))
			return
		}
		challenge := r.Form.Get("challenge")
		subject := r.Form.Get("subject")
		email := r.Form.Get("email")
		if challenge == "" || subject == "" || email == "" {
			badRequestError(w, fmt.Errorf("Missing field in form data"))
			return
		}
		grantScope := r.Form["grant_scope"]
		var accessGranted bool
		if r.Form.Get("submit") == "Allow access" {
			accessGranted = true
		}

		if !accessGranted {
			rejectConsent(w, r, challenge, subject)
		} else {
			acceptConsent(w, r, challenge, subject, email, false, grantScope)
		}

		return
	}

	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		badRequestError(w, fmt.Errorf("Missing challenge argument: %s", r.URL.String()))
		return
	}

	v, err := getConsentStatus(challenge)
	if err != nil {
		internalError(w, err)
		return
	}

	email, err := getEmailFromSubject(v.Subject)
	if err != nil {
		internalError(w, err)
		return
	}

	if v.Skip {
		acceptConsent(w, r, challenge, v.Subject, email, v.Skip, v.RequestedScope)
	}

	showConsentForm(w, r, challenge, email, v)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Callback")
}

func internalError(w http.ResponseWriter, err error) {
	log.Print(err)
	w.WriteHeader(http.StatusInternalServerError)
}

func badRequestError(w http.ResponseWriter, err error) {
	log.Print(err)
	w.WriteHeader(http.StatusBadRequest)
}

func getLoginStatus(challenge string) (v LoginStatusRes, err error) {
	var res *http.Response
	url := config.Hydra.LoginURL + challenge
	res, err = http.Get(url)
	if err != nil {
		err = fmt.Errorf("Request failed: %s", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("Request failed: %s: %s", url, res.Status)
		return
	}

	d := json.NewDecoder(res.Body)
	err = d.Decode(&v)
	if err != nil {
		err = fmt.Errorf("Body decoding failed: %s", err)
		return
	}

	return
}

func acceptLogin(w http.ResponseWriter, r *http.Request, challenge, subject string, skip bool) {
	log.Println("Login accepted:", challenge, subject)

	req := LoginAcceptReq{
		Subject: subject,
	}
	if !skip {
		req.Remember = true
		req.RememberFor = halfYear
	}
	b, err := json.Marshal(req)
	if err != nil {
		internalError(w, err)
		return
	}

	url := config.Hydra.LoginURL + challenge + "/accept"
	res, err := putJSON(url, b)
	if err != nil {
		internalError(w, err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		internalError(w, fmt.Errorf("Request failed: %s: %s", url, res.Status))
		return
	}

	var v RedirectRes
	d := json.NewDecoder(res.Body)
	err = d.Decode(&v)
	if err != nil {
		internalError(w, err)
		return
	}

	http.Redirect(w, r, v.RedirectTo, http.StatusFound)
}

func rejectLogin(w http.ResponseWriter, r *http.Request, challenge, subject string) {

}

func executeTemplate(w http.ResponseWriter, templatePath string, data map[string]interface{}) {
	t, err := template.ParseFiles(templatePath)
	if err == nil {
		err = t.Execute(w, data)
	}
	if err != nil {
		internalError(w, err)
	}
}

func showLoginForm(w http.ResponseWriter, r *http.Request, challenge string) {
	executeTemplate(w, "templates/loginForm.html", map[string]interface{}{"challenge": challenge})
}

func showConsentForm(w http.ResponseWriter, r *http.Request, challenge, email string, consent ConsentStatusRes) {
	scope := []string{}
LOOP:
	for _, s := range consent.RequestedScope {
		for _, s2 := range config.DefaultScope {
			if s == s2 {
				continue LOOP
			}
		}
		scope = append(scope, s)
	}

	executeTemplate(w, "templates/consentForm.html", map[string]interface{}{
		"challenge":      challenge,
		"subject":        consent.Subject,
		"email":          email,
		"clientName":     consent.Client.Name,
		"requestedScope": scope,
	})
}

func sendConfirmEmail(w http.ResponseWriter, r *http.Request, email, challenge, subject string) {
	id, err := storeLoginStatus(challenge, email, subject)
	if err != nil {
		internalError(w, err)
		return
	}

	// subject := "Please Verify Your Email Address"
	// req := NewRequest([]string{email}, subject)
	// req.Send("templates/confirmMail.html", map[string]string{"confirmLink": config.ConfirmLink + id})

	fmt.Fprintf(w, `
<html>
<body>
<h1>Mail was sent</h1>
<p>DEBUG: <a href="%s">Confirmation link</a></p>
</body>
</html>`, config.ConfirmLink+id)
}

func storeLoginStatus(challenge, email, subject string) (string, error) {
	var id, key string
	for {
		id = ksuid.New().String()
		key = "login-context:" + id
		b, err := json.Marshal(LoginContext{
			Challenge: challenge,
			Email:     email,
			Subject:   subject,
		})
		if err != nil {
			return "", err
		}
		ok, err := redisClient.SetNX(key, string(b), 24*time.Hour).Result()
		if err != nil {
			return "", fmt.Errorf("Error setting key %s: %s", key, err)
		}
		if ok {
			break
		}
	}

	return id, nil
}

func confirmMailHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	s, err := redisClient.Get("login-context:" + id).Result()
	if err != nil {
		if err == redis.Nil {
			// XXX 404 link timed out bo neco takoveho
			panic("XXX")
		}
		internalError(w, err)
		return
	}
	var ctx LoginContext
	err = json.Unmarshal([]byte(s), &ctx)
	if err != nil {
		internalError(w, err)
		return
	}

	if ctx.Subject == "" {
		ctx.Subject, err = makeSubject(ctx.Email)
		if err != nil {
			internalError(w, fmt.Errorf("Error getting subject for email %s: %s", ctx.Email, err))
			return
		}
	}

	v, err := getLoginStatus(ctx.Challenge)
	if err != nil {
		internalError(w, err)
		return
	}
	var subject string
	if v.Skip {
		subject = v.Subject
	} else {
		subject = ctx.Subject
	}

	acceptLogin(w, r, ctx.Challenge, subject, v.Skip)
}

func putJSON(url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func getConsentStatus(challenge string) (v ConsentStatusRes, err error) {
	var (
		res *http.Response
	)
	url := config.Hydra.ConsentURL + challenge
	res, err = http.Get(url)
	if err != nil {
		err = fmt.Errorf("Request failed: %s", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("Request failed: %s: %s", url, res.Status)
		return
	}

	d := json.NewDecoder(res.Body)
	err = d.Decode(&v)
	if err != nil {
		err = fmt.Errorf("Body decoding failed: %s", err)
		return
	}

	return
}

func acceptConsent(w http.ResponseWriter, r *http.Request, challenge, subject, email string, skip bool, grantScope []string) {
LOOP:
	for _, s := range config.DefaultScope {
		for _, s2 := range grantScope {
			if s == s2 {
				continue LOOP
			}
		}
		grantScope = append(grantScope, s)
	}

	log.Println("Consent accepted:", challenge, subject, grantScope)

	req := ConsentAcceptReq{
		GrantScope: grantScope,
	}
	req.Session.AccessToken = map[string]interface{}{
		"email": email,
	}
	if !skip {
		req.Remember = true
		req.RememberFor = halfYear
	}
	b, err := json.Marshal(req)
	if err != nil {
		internalError(w, err)
		return
	}

	url := config.Hydra.ConsentURL + challenge + "/accept"
	res, err := putJSON(url, b)
	if err != nil {
		internalError(w, err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		internalError(w, fmt.Errorf("Request failed: %s: %s", url, res.Status))
		return
	}

	var v RedirectRes
	d := json.NewDecoder(res.Body)
	err = d.Decode(&v)
	if err != nil {
		internalError(w, err)
		return
	}

	http.Redirect(w, r, v.RedirectTo, http.StatusFound)
}

func rejectConsent(w http.ResponseWriter, r *http.Request, challenge, subject string) {
	log.Println("Consent rejected:", challenge, subject)

	b, err := json.Marshal(RejectReq{
		Error:      "access_denied",
		ErrorDescr: "The resource owner denied the request",
	})
	if err != nil {
		internalError(w, err)
		return
	}

	url := config.Hydra.ConsentURL + challenge + "/reject"
	res, err := putJSON(url, b)
	if err != nil {
		internalError(w, err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		internalError(w, fmt.Errorf("Request failed: %s: %s", url, res.Status))
	}

	var v RedirectRes
	d := json.NewDecoder(res.Body)
	err = d.Decode(&v)
	err = json.Unmarshal(b, &v)
	if err != nil {
		internalError(w, err)
		return
	}

	http.Redirect(w, r, v.RedirectTo, http.StatusFound)
}

func getSubjectFromEmail(email string) (subject string, err error) {
	subject, err = redisClient.Get("email2subject:" + email).Result()
	return
}

func getEmailFromSubject(subject string) (email string, err error) {
	email, err = redisClient.Get("subject2email:" + subject).Result()
	return
}

func makeSubject(email string) (subject string, err error) {
	id := ksuid.New().String()
	var ok bool
	ok, err = redisClient.SetNX("email2subject:"+email, id, 0).Result()
	if err != nil {
		return
	}
	if ok {
		subject = id
		_, err = redisClient.Set("subject2email:"+subject, email, 0).Result()
		// TODO remove email2subject
	} else {
		subject, err = getSubjectFromEmail(email)
	}

	return
}
