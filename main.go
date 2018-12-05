package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
	"github.com/segmentio/ksuid"
)

const halfYear = 6 * 30 * 24 * 3600

const LoginMessage = "Login to Trezor Cloud"

var (
	config      = Config{}
	redisClient *redis.Client
)

var AlreadyRegisteredError = errors.New("Already registered")

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

type AccountRegistrationContext struct {
	Email string `json:"email"`
}

type DeviceRegistrationContext struct {
	Account   string `json:"account"`
	Challenge string `json:"challenge,omitempty"`
}

type DeviceInfo struct {
	Account   string `json:"account"`
	Label     string `json:"label"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

type LoginContext struct {
	Challenge string `json:"challenge"`
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

	router.HandleFunc("/login", loginHandler).Methods("GET")
	router.HandleFunc("/login/challenge/{challenge}", loginChallengeHandler).Methods("GET")
	router.HandleFunc("/login/verify/{challenge}", loginVerifyHandler).Methods("POST")
	router.HandleFunc("/consent", consentHandler).Methods("GET", "POST")
	router.HandleFunc("/register", registerHandler).Methods("GET", "POST")
	router.HandleFunc("/register/confirm/{id}", confirmRegistrationHandler).Methods("GET")
	router.HandleFunc("/register/device/{challenge}", deviceRegistrationChallengeHandler).Methods("GET")
	router.HandleFunc("/register/device/verify/{challenge}", deviceRegistrationVerifyHandler).Methods("POST")
	router.HandleFunc("/register/done", registrationDoneHandler).Methods("POST")
	// router.HandleFunc("/reset", resetHandler).Methods("GET", "POST")
	// router.HandleFunc("/reset/confirm/{id}", confirmResetHandler).Methods("GET", "POST")

	router.PathPrefix("/js/").Handler(http.StripPrefix("/js/", http.FileServer(http.Dir("js"))))
	router.PathPrefix("/css/").Handler(http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))

	http.ListenAndServeTLS(config.ListenAddr, "cert/server.crt", "cert/server.key", router)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			badRequestError(w, fmt.Errorf("Form parsing failed: %s", err))
			return
		}
		email := r.Form.Get("email")
		if email == "" {
			badRequestError(w, fmt.Errorf("Invalid parameters: %+v", r.Form))
			return
		}

		sendRegistrationEmail(w, r, email)
		return
	}

	showRegistrationForm(w, r)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
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

	showLoginPage(w, r, challenge)
}

func loginChallengeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	challenge := vars["challenge"]

	id := hex.EncodeToString(ksuid.New().Bytes())
	ctx := LoginContext{Challenge: id}
	err := storeLoginContext(challenge, &ctx)
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	err = e.Encode(map[string]string{
		"challengeHidden": id,
		"challengeVisual": LoginMessage,
	})
	if err != nil {
		log.Println(err)
	}
}

func loginVerifyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	challenge := vars["challenge"]

	err := r.ParseForm()
	if err != nil {
		badRequestError(w, err)
		return
	}

	address := r.Form.Get("address")
	publicKey := r.Form.Get("publicKey")
	signature := r.Form.Get("signature")

	if address == "" || publicKey == "" || signature == "" {
		badRequestError(w, fmt.Errorf("Invalid parameters: %+v", r.Form))
		return
	}

	ctx, err := getLoginContext(challenge)
	if err != nil {
		internalError(w, err)
		return
	}

	log.Printf("login verify params: address=%q, publicKey=%q, signature=%q, challenge=%q",
		address, publicKey, signature, ctx.Challenge)

	valid, err := verifyTrezorLogin(ctx.Challenge, LoginMessage, publicKey, signature)

	if err != nil {
		internalError(w, err)
		return
	}

	if !valid {
		log.Printf("Reject login: %s", publicKey)
		rejectLogin(w, r, challenge)
		return
	}

	di, err := getDeviceInfo(publicKey)
	if err != nil {
		internalError(w, err)
		return
	}

	if di == nil {
		log.Printf("Reject login: device=%s", publicKey)
		rejectLogin(w, r, challenge)
		return
	}

	log.Printf("Accept login: device=%s, account=%s", publicKey, di.Account)
	acceptLogin(w, r, challenge, di.Account, false)
}

func storeLoginContext(id string, ctx *LoginContext) error {
	b, err := json.Marshal(ctx)
	if err != nil {
		return err
	}

	key := "login-context:" + id
	err = redisClient.Set(key, string(b), time.Hour).Err()
	if err != nil {
		return fmt.Errorf("Error setting key %s: %s", key, err)
	}

	return nil
}

func getLoginContext(id string) (*LoginContext, error) {
	key := "login-context:" + id
	s, err := redisClient.Get(key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("Not found: %s", key)
		}
		return nil, err
	}
	var v *LoginContext
	err = json.Unmarshal([]byte(s), &v)
	if err != nil {
		return nil, err
	}

	return v, nil
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

	email, err := getEmailFromAccount(v.Subject)
	if err != nil {
		internalError(w, err)
		return
	}

	if v.Skip {
		acceptConsent(w, r, challenge, v.Subject, email, v.Skip, v.RequestedScope)
	}

	showConsentForm(w, r, challenge, email, v)
}

func internalError(w http.ResponseWriter, err error) {
	log.Print(err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

func badRequestError(w http.ResponseWriter, err error) {
	log.Print(err)
	http.Error(w, "Bad request", http.StatusBadRequest)
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

	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	err = e.Encode(v)
	if err != nil {
		log.Println(err)
	}
}

func rejectLogin(w http.ResponseWriter, r *http.Request, challenge string) {
	log.Println("Login rejected:", challenge)

	b, err := json.Marshal(RejectReq{
		Error:      "authentication_failure",
		ErrorDescr: "Provided device doesn't match any account",
	})
	if err != nil {
		internalError(w, err)
		return
	}

	url := config.Hydra.LoginURL + challenge + "/reject"
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

	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	err = e.Encode(v)
	if err != nil {
		log.Println(err)
	}
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

func showLoginPage(w http.ResponseWriter, r *http.Request, challenge string) {
	executeTemplate(w, "templates/login.html", map[string]interface{}{"challenge": challenge})
}

func showRegistrationForm(w http.ResponseWriter, r *http.Request) {
	executeTemplate(w, "templates/registrationForm.html", nil)
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

func sendRegistrationEmail(w http.ResponseWriter, r *http.Request, email string) {
	id, err := storeAccountRegistrationContext(email)
	if err != nil {
		internalError(w, err)
		return
	}

	subject := "Please Verify Your Email Address"
	req := NewRequest([]string{email}, subject)
	req.Send("templates/registrationEmail.html", map[string]string{"confirmLink": config.ConfirmLink + id})

	executeTemplate(w, "templates/registrationEmailSent.html", nil)
}

func storeAccountRegistrationContext(email string) (string, error) {
	var id, key string
	for {
		id = ksuid.New().String()
		key = "account-registration-context:" + id
		b, err := json.Marshal(AccountRegistrationContext{
			Email: email,
		})
		if err != nil {
			return "", err
		}
		ok, err := redisClient.SetNX(key, string(b), time.Hour).Result()
		if err != nil {
			return "", fmt.Errorf("Error setting key %s: %s", key, err)
		}
		if ok {
			break
		}
	}

	return id, nil
}

func confirmRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	s, err := redisClient.Get("account-registration-context:" + id).Result()
	if err != nil {
		if err == redis.Nil {
			executeTemplate(w, "templates/linkExpired.html", nil)
			return
		}
		internalError(w, err)
		return
	}
	var ctx AccountRegistrationContext
	err = json.Unmarshal([]byte(s), &ctx)
	if err != nil {
		internalError(w, err)
		return
	}

	account, err := getAccountFromEmail(ctx.Email)
	if err != nil {
		internalError(w, fmt.Errorf("Error getting account for email %s: %s", ctx.Email, err))
		return
	}
	if account != "" {
		log.Printf("Account already registered: email=%s, id=%s", ctx.Email, account)
		executeTemplate(w, "templates/alreadyRegistered.html", nil)
		return
	}

	// XXX set timeout for an account until the user done a device registration
	account, err = makeAccount(ctx.Email)
	if err != nil {
		internalError(w, fmt.Errorf("Error getting account for email %s: %s", ctx.Email, err))
		return
	}

	showDeviceRegistrationForm(w, r, account)
}

func showDeviceRegistrationForm(w http.ResponseWriter, r *http.Request, account string) {
	id, err := storeDeviceRegistrationContext(account)
	if err != nil {
		internalError(w, err)
		return
	}

	executeTemplate(w, "templates/deviceRegisterForm.html", map[string]interface{}{
		"challenge": id,
	})
}

func storeDeviceRegistrationContext(account string) (string, error) {
	var id, key string
	for {
		id = ksuid.New().String()
		key = "device-register-context:" + id
		b, err := json.Marshal(DeviceRegistrationContext{
			Account: account,
		})
		if err != nil {
			return "", err
		}
		ok, err := redisClient.SetNX(key, string(b), time.Hour).Result()
		if err != nil {
			return "", fmt.Errorf("Error setting key %s: %s", key, err)
		}
		if ok {
			break
		}
	}

	return id, nil
}

func deviceRegistrationChallengeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	challenge := vars["challenge"]

	id := hex.EncodeToString(ksuid.New().Bytes())

	err := updateDeviceRegisterContext(challenge, func(ctx *DeviceRegistrationContext) {
		ctx.Challenge = id
	})
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	err = e.Encode(map[string]string{
		"challengeHidden": id,
		"challengeVisual": LoginMessage,
	})
	if err != nil {
		log.Println(err)
	}
}

func deviceRegistrationVerifyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	challenge := vars["challenge"]

	err := r.ParseForm()
	if err != nil {
		badRequestError(w, err)
		return
	}

	label := r.Form.Get("label")
	address := r.Form.Get("address")
	publicKey := r.Form.Get("publicKey")
	signature := r.Form.Get("signature")

	if label == "" || address == "" || publicKey == "" || signature == "" {
		badRequestError(w, fmt.Errorf("Invalid parameters: %+v", r.Form))
		return
	}

	ctx, err := getDeviceRegisterContext(challenge)
	if err != nil {
		internalError(w, err)
		return
	}

	log.Printf("registration verify params: label=%q, address=%q, publicKey=%q, signature=%q, challenge=%q",
		label, address, publicKey, signature, ctx.Challenge)

	valid, err := verifyTrezorLogin(ctx.Challenge, LoginMessage, publicKey, signature)

	if err != nil {
		internalError(w, err)
		return
	}

	if !valid {
		http.Error(w, "Device verification failed", http.StatusForbidden)
		return
	}

	deviceID, err := registerDevice(ctx.Account, label, address, publicKey)
	if err != nil {
		if err == AlreadyRegisteredError {
			log.Printf("Device already registered: publicKey=%q, account=%q", publicKey, ctx.Account)
			http.Error(w, "Device already registered", http.StatusConflict)
		} else {
			internalError(w, err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	e := json.NewEncoder(w)
	err = e.Encode(map[string]string{
		"deviceID":    deviceID,
		"deviceLabel": label,
	})
	if err != nil {
		log.Println(err)
	}
}

func verifyTrezorLogin(challengeHidden, challengeVisual, publicKey, signature string) (bool, error) {
	challengeHiddenBytes, err := hex.DecodeString(challengeHidden)
	if err != nil {
		return false, fmt.Errorf("Error decoding challenge: %s: %s", challengeHidden, err)
	}

	h1 := sha256Hash(challengeHiddenBytes)
	h2 := sha256Hash([]byte(challengeVisual))

	var msg [64]byte
	copy(msg[:32], h1)
	copy(msg[32:], h2)

	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Bitcoin Signed Message:\n")
	wire.WriteVarString(&buf, 0, string(msg[:]))
	messageHash := chainhash.DoubleHashB(buf.Bytes())

	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, fmt.Errorf("Error decoding public key: %s: %s", publicKey, err)
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		return false, fmt.Errorf("Error parsing public key: %s: %s", publicKey, err)
	}

	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("Error decoding signature: %s: %s", signature, err)
	}

	if !(27 <= signatureBytes[0] && signatureBytes[0] <= 34) {
		return false, fmt.Errorf("Error decoding signature: %s: %d must be in range 27-34", signature, signatureBytes[0])
	}

	sig := btcec.Signature{
		R: new(big.Int).SetBytes(signatureBytes[1:33]),
		S: new(big.Int).SetBytes(signatureBytes[33:]),
	}

	return sig.Verify(messageHash, pubKey), nil
}

func sha256Hash(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil)
}

func getDeviceRegisterContext(id string) (*DeviceRegistrationContext, error) {
	key := "device-register-context:" + id
	s, err := redisClient.Get(key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("Not found: %s", key)
		}
		return nil, err
	}
	var v *DeviceRegistrationContext
	err = json.Unmarshal([]byte(s), &v)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func updateDeviceRegisterContext(id string, updateFn func(*DeviceRegistrationContext)) error {
	key := "device-register-context:" + id
	s, err := redisClient.Get(key).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("Not found: %s", key)
		}
		return err
	}
	var v DeviceRegistrationContext
	err = json.Unmarshal([]byte(s), &v)
	if err != nil {
		return err
	}

	updateFn(&v)

	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	ttl, err := redisClient.TTL(key).Result()
	if err != nil {
		return err
	}

	return redisClient.Set(key, string(b), ttl).Err()
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

func getAccountFromEmail(email string) (string, error) {
	account, err := redisClient.Get("email2account:" + email).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}
	return account, nil
}

func getEmailFromAccount(account string) (string, error) {
	email, err := redisClient.Get("account2email:" + account).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}
	return email, nil
}

func makeAccount(email string) (account string, err error) {
	id := ksuid.New().String()
	var ok bool
	ok, err = redisClient.SetNX("email2account:"+email, id, 0).Result()
	if err != nil {
		return
	}
	if ok {
		account = id
		_, err = redisClient.Set("account2email:"+account, email, 0).Result()
		// TODO remove email2account if err
	} else {
		account, err = getAccountFromEmail(email)
	}

	return
}

// func resetHandler(w http.ResponseWriter, r *http.Request) {
// }
//
// func confirmResetHandler(w http.ResponseWriter, r *http.Request) {
// 	// TODO pro reset pridat expiraci linku
// }

func getDeviceInfo(id string) (*DeviceInfo, error) {
	s, err := redisClient.Get("device:" + id).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	var info DeviceInfo
	err = json.Unmarshal([]byte(s), &info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func registerDevice(account, label, address, publicKey string) (string, error) {
	// XXX transaction

	id := publicKey
	info := DeviceInfo{
		Account:   account,
		Label:     label,
		Address:   address,
		PublicKey: publicKey,
	}

	b, err := json.Marshal(info)
	if err != nil {
		return "", err
	}

	key := "device:" + id
	ok, err := redisClient.SetNX(key, string(b), 0).Result()
	if err != nil {
		return "", fmt.Errorf("Error setting key %s: %s", key, err)
	}
	if !ok {
		return "", AlreadyRegisteredError
	}

	err = redisClient.LPush("account_devices:"+account, id).Err()
	if err != nil {
		if err := redisClient.Del(key).Err(); err != nil {
			log.Printf("Failed recovery delete of device, database may stay in inconsistent state: account=%q, device=%q, err=%q", account, id, err)
		}
		return "", fmt.Errorf("Error adding device to account: account=%q, device=%q, err=%q", account, id, err)
	}

	return id, nil
}

func getAccountDevices(account string) ([]string, error) {
	slice, err := redisClient.LRange("account_devices:"+account, 0, -1).Result()
	if err != nil {
		if err == redis.Nil {
			return []string{}, nil
		}
		return nil, err
	}
	return slice, nil
}

func registrationDoneHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		badRequestError(w, err)
		return
	}

	challenge := r.Form.Get("challenge")

	if challenge == "" {
		badRequestError(w, fmt.Errorf("Invalid parameters: empty challenge"))
		return
	}

	ctx, err := getDeviceRegisterContext(challenge)
	if err != nil {
		internalError(w, err)
		return
	}

	devices, err := getAccountDevices(ctx.Account)
	if err != nil {
		internalError(w, err)
		return
	}

	if len(devices) == 0 {
		html := []byte(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Precondition required</title>
</head>
<body>
	<h1>Precondition required</h1>
	<p>This request is required to be conditional;
	follow registration flow</p>
</body>
</html>`)
		w.WriteHeader(http.StatusPreconditionRequired)
		w.Write(html)
		return
	}

	executeTemplate(w, "templates/registrationDone.html", map[string]interface{}{
		"login_title": config.LoginPage.Title,
		"login_url":   config.LoginPage.URL,
	})
}
