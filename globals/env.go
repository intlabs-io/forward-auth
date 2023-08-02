// package globals defines global constants and variables dot-imported throughout the application

package globals

import (
	"bitbucket.org/_metalogic_/config"
)

var (
	FROM_EMAIL       string
	SENDGRID_API_KEY string
)

func init() {
	FROM_EMAIL = config.IfGetenv("MAILER", "dev@roderickmorrison.net")
	SENDGRID_API_KEY = config.IfGetenv("SENDGRID_API_KEY", "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")
}
