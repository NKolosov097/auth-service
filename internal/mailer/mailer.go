package mailer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
)

type Mailer struct {
	host        string
	port        int
	username    string
	password    string
	from        string
	implicitTLS bool // true = port 465; false = STARTTLS (port 587)
}

func New(host string, port int, username, password, from string, implicitTLS bool) *Mailer {
	return &Mailer{
		host:        host,
		port:        port,
		username:    username,
		password:    password,
		from:        from,
		implicitTLS: implicitTLS,
	}
}

func (m *Mailer) SendPasswordReset(to, token, appURL string) error {
	link := fmt.Sprintf("%s/reset-password?token=%s", appURL, token)
	body := fmt.Sprintf("Click the link to reset your password (valid 1 hour):\n\n%s", link)
	return m.send(to, "Password Reset", body)
}

func (m *Mailer) SendEmailChange(to, token, appURL string) error {
	link := fmt.Sprintf("%s/confirm-email-change?token=%s", appURL, token)
	body := fmt.Sprintf("Click the link to confirm your new email address (valid 24 hours):\n\n%s", link)
	return m.send(to, "Confirm Email Change", body)
}

func (m *Mailer) send(to, subject, body string) error {
	// H8: guard against SMTP header injection via user-supplied addresses
	if strings.ContainsAny(to, "\r\n") {
		return fmt.Errorf("invalid recipient address")
	}
	if _, err := mail.ParseAddress(to); err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}

	addr := net.JoinHostPort(m.host, fmt.Sprintf("%d", m.port))
	if m.implicitTLS {
		return m.sendImplicitTLS(addr, to, subject, body)
	}
	return m.sendSTARTTLS(addr, to, subject, body)
}

func (m *Mailer) sendSTARTTLS(addr, to, subject, body string) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer c.Close()

	tlsCfg := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}
	ok, _ := c.Extension("STARTTLS")
	if !ok {
		return fmt.Errorf("smtp server does not advertise STARTTLS")
	}
	if err := c.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}
	if err := c.Auth(smtp.PlainAuth("", m.username, m.password, m.host)); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	return m.writeMessage(c, to, subject, body)
}

func (m *Mailer) sendImplicitTLS(addr, to, subject, body string) error {
	tlsCfg := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Close()

	if err := c.Auth(smtp.PlainAuth("", m.username, m.password, m.host)); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	return m.writeMessage(c, to, subject, body)
}

func (m *Mailer) writeMessage(c *smtp.Client, to, subject, body string) error {
	if err := c.Mail(m.from); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	msg := strings.Join([]string{
		"From: " + m.from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
	}, "\r\n")
	if _, err := fmt.Fprint(wc, msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return c.Quit()
}
