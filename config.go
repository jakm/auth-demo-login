package main

import (
	"io/ioutil"
	"log"

	"github.com/joeshaw/envdecode"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Mail struct {
		From string `yaml:"from" env:"MAIL_FROM"`
		Smtp struct {
			Server   string `yaml:"server" env:"SMTP_SERVER"`
			Port     uint16 `yaml:"port"   env:"SMTP_PORT"`
			User     string `yaml:"user"   env:"SMTP_USER"`
			Password string `yaml:"pass"   env:"SMTP_PASS"`
		} `yaml:"smtp"`
	} `yaml:"mail"`
	Redis struct {
		Addr     string `yaml:"addr" env:"REDIS_ADDR"`
		Password string `yaml:"pass" env:"REDIS_PASS"`
		DB       int    `yaml:"db"   env:"REDIS_DB"`
	} `yaml:"redis"`
	Hydra struct {
		LoginURL   string `yaml:"login_url"   env:"HYDRA_LOGIN_URL"`
		ConsentURL string `yaml:"consent_url" env:"HYDRA_CONSENT_URL"`
	} `yaml:"hydra"`
	Keto struct {
		PoliciesURL string `yaml:"policies_url" env:"KETO_POLICIES_URL"`
	} `yaml:"keto"`
	LoginPage struct {
		Title string `yaml:"title" env:"LOGIN_PAGE_TITLE"`
		URL   string `yaml:"url"   env:"LOGIN_PAGE_URL"`
	} `yaml:"login_page"`
	ConfirmLink  string   `yaml:"confirm_link"  env:"CONFIRM_LINK"`
	DefaultScope []string `yaml:"default_scope" env:"DEFAULT_SCOPE"`
	ListenAddr   string   `yaml:"listen_addr"   env:"LISTEN_ADDR"`
}

func (c *Config) Load() error {
	b, err := ioutil.ReadFile("config.yaml")
	if err == nil {
		err = yaml.Unmarshal(b, &c)
	}
	if err != nil {
		log.Printf("WARNING: Could not load config file: %s", err)
	}
	err = envdecode.Decode(c)
	return err
}
