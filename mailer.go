package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
)

type Request struct {
	from    string
	to      []string
	subject string
	body    string
}

const (
	MIME = "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
)

func NewRequest(to []string, subject string) *Request {
	return &Request{
		from:    config.Mail.From,
		to:      to,
		subject: subject,
	}
}

func (r *Request) parseTemplate(fileName string, data interface{}) error {
	t, err := template.ParseFiles(fileName)
	if err != nil {
		return err
	}
	buffer := new(bytes.Buffer)
	if err = t.Execute(buffer, data); err != nil {
		return err
	}
	r.body = buffer.String()
	return nil
}

func (r *Request) sendMail() error {
	body := "To: " + r.to[0] + "\r\nFrom: " + r.from + "\r\nSubject: " + r.subject + "\r\n" + MIME + "\r\n" + r.body
	SMTP := fmt.Sprintf("%s:%d", config.Mail.Smtp.Server, config.Mail.Smtp.Port)
	err := smtp.SendMail(SMTP, smtp.PlainAuth("", config.Mail.Smtp.User, config.Mail.Smtp.Password, config.Mail.Smtp.Server), config.Mail.From, r.to, []byte(body))
	return err
}

func (r *Request) Send(templateName string, items interface{}) error {
	err := r.parseTemplate(templateName, items)
	if err == nil {
		err = r.sendMail()
	}
	return err
}
