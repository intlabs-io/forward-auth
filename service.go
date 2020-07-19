package fauth

// Service ...
type Service interface {
	Auth(host, method, path, token, jwt string) (status int, message, user string, err error)
	Block(user string)
	Blocked() []string
	Close()
	Health() error
	Info() string
	RunMode() string
	SetRunMode(string)
	Stats() string
	Unblock(user string)
	Version() string
}
