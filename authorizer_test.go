package fauth_test

import (
	"io/ioutil"
	"testing"

	fauth "bitbucket.org/_metalogic_/forward-auth"
	"bitbucket.org/_metalogic_/forward-auth/stores/mock"
	"bitbucket.org/_metalogic_/log"
)

const (
	sessionMode = "cookie"
	sessionName = "test-session"
	jwtHeader   = "test"
)

var (
	auth      *fauth.Auth
	publicKey []byte
	blocks    map[string]bool
	tokens    map[string]string
	secret    []byte
	// new
	keyFile    = "test/dev-q84yaa6r.pem"
	rickyToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InYxRHZZRFF5NG5IOVlGNWd5U0RCaiJ9.eyJuYW1lIjoiUmlja3kgTW9ycmlzb24iLCJlbWFpbCI6InJpY2t5QGludGxhYnMuaW8iLCJpZGVudGl0eSI6eyJjbGFzc2lmaWNhdGlvbiI6Ik5PTkUiLCJkZXNjcmlwdGlvbiI6IlJpY2t5IE1vcnJpc29uIiwiZG9tYWluIjoiaW8uaW50bGFicyIsIm1ldGEiOnsiY3JlYXRlZCI6IjIwMjItMTAtMjRUMDc6MzY6MDIuMDUyNjgrMDA6MDAiLCJjcmVhdGV1c2VyIjoiT1JJR0lOIiwidXBkYXRlZCI6bnVsbCwidXBkYXRldXNlciI6bnVsbH0sIm5hbWUiOiJyaWNreSIsInN1cGVydXNlciI6ZmFsc2UsInVpZCI6Imdvb2dsZS1vYXV0aDJ8MTE2MjgyMDc1Mzc3MDM4Mzg1NDkyIn0sImlzcyI6Imh0dHBzOi8vZGV2LXE4NHlhYTZyLnVzLmF1dGgwLmNvbS8iLCJzdWIiOiJnb29nbGUtb2F1dGgyfDExNjI4MjA3NTM3NzAzODM4NTQ5MiIsImF1ZCI6WyJodHRwOi8vb3JpZ2luLWFwaXMubG9jYWxob3N0IiwiaHR0cHM6Ly9kZXYtcTg0eWFhNnIudXMuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTY2Njc5NTAzNywiZXhwIjoxNjY2ODgxNDM3LCJhenAiOiJTUVlKR2J5VFFrczdsVU96VVFENEV1U1hIM3d6SnJVeCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwifQ.EeTKX_fzIz1C1IVGOZthngBAAsGpuYrFS0R8L-QbiLBeavAZ_qhXQ4cy6sxzMj2RURSkpe47UqIdElSK-jqRPviKPknLZ3cHoWq0cPZJR_giR8cMyZJ9DgRCp1stWP_968j-VWBo-ntq47C69NJkIHXC20m0cBnKumjkPgRrfpdn6U8rQI9ntFT0PLZgvP653r6dN1Qo4noLbYMLQFbsbZNUAO4to6xZWp-p7Looc6qFtQldffHFw4DwkLVIXLi83hglgvXy-7hoT6um1OWjlepC43LLkurLUMqpn4ERFnYJRFhbwwtc25ZJUhJmZKWKVS9QgBqPD7vvKDR2p7vHKw"
	rickyJWT   = `{
		"name": "Ricky Morrison",
		"email": "ricky@intlabs.io",
		"identity": {
		  "uid": "google-oauth2|116282075377038385492",
		  "classification": {
			"authority": "standard",
			"level": "NONE"
		  },
		  "description": "Ricky Morrison",
		  "domain": "io.intlabs",
		  "name": "ricky",
		  "superuser": false,
		  "meta": {
			"created": "2022-10-24T07:36:02.05268+00:00",
			"createuser": "ORIGIN",
			"updated": null,
			"updateuser": null
		  }
		},
		"iss": "https://dev-q84yaa6r.us.auth0.com/",
		"sub": "google-oauth2|116282075377038385492",
		"aud": [
		  "http://origin-apis.localhost",
		  "https://dev-q84yaa6r.us.auth0.com/userinfo"
		],
		"iat": 1666782112,
		"exp": 1666868512,
		"azp": "SQYJGbyTQks7lUOzUQD4EuSXH3wzJrUx",
		"scope": "openid profile email"
	}`
)

func init() {
	var err error
	publicKey, err = ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatal(err)
	}
	secret = []byte("RyxDWzqg8AaDAHxGt989tEPdfG42dr6e5QqCxJ4mwGKYavtLbj")
	store, err := mock.New()
	if err != nil {
		log.Fatal(err)
	}
	acs, err := store.Load()
	if err != nil {
		log.Fatal(err)
	}
	auth, err = fauth.NewAuth(acs, sessionMode, sessionName, jwtHeader, publicKey, secret)
	if err != nil {
		log.Fatal(err)
	}
}
func Test_checkJWT(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	type args struct {
		keyType     string
		key         []byte
		tokenString string
	}

	type wants struct {
		uid            string
		email          string
		root           bool
		classification string
	}

	tests := []struct {
		name  string
		args  args
		wants wants
	}{
		{
			"Ricky claims",
			args{
				keyType:     "rsa",
				key:         publicKey,
				tokenString: rickyToken,
			},
			wants{
				"google-oauth2|116282075377038385492",
				"ricky@intlabs.io",
				false,
				"NONE",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := auth.JWTIdentity(tt.args.tokenString)
			if err == nil {
				if identity.Superuser != tt.wants.root {
					t.Errorf("%s: identity.Root = %t, want %t", tt.name, identity.Superuser, tt.wants.root)
				}
				if *identity.Email != tt.wants.email {
					t.Errorf("%s: identity.Name = %s, want %s", tt.name, *identity.Email, tt.wants.email)
				}
				if *identity.UID != tt.wants.uid {
					t.Errorf("%s: identity.UID = %s, want %s", tt.name, *identity.UID, tt.wants.uid)
				}
			} else {
				t.Errorf("%s: %s", tt.name, err)
			}
			if identity == nil {
				t.Errorf("%s: identity not found in token", tt.name)
			}

		})
	}
}
