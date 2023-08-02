package server

import (
	"fmt"
	"net/http"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"

	. "bitbucket.org/_metalogic_/forward-auth/globals"
)

func sendEmail(recipient, subject, body string) (err error) {
	from := mail.NewEmail("Auth Mailer", FROM_EMAIL)
	// TODO NewEmail accepts a user name as first argument
	to := mail.NewEmail("", recipient)
	message := mail.NewSingleEmail(from, subject, to, body, "")
	client := sendgrid.NewSendClient(SENDGRID_API_KEY)
	res, err := client.Send(message)
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusAccepted {
		return fmt.Errorf("Sendgrid send to recipient %s failed with status %d: %s", recipient, res.StatusCode, res.Body)
	}
	if err != nil {
		return fmt.Errorf("Sendgrid send to recipient %s failed with error %s: %s", recipient, err, res.Body)
	}

	return nil
}
