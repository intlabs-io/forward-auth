package fauth

import (
	"io/ioutil"
	"testing"

	"bitbucket.org/_metalogic_/log"
)

const (
	jwtHeader = "test"
)

var (
	auth      *Auth
	publicKey []byte
	blocks    map[string]bool
	tokens    map[string]string
	secret    []byte
	// new
	keyFile = "test/new-public.key"
	adamTkn = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRFQjcxODhFMzhGOTgyNEY2M0QyQTRFQzdEMjNEMjAxREYyRTZBMjFSUzI1NiIsInR5cCI6ImF0K2p3dCIsIng1dCI6IlRyY1lqamo1Z2s5ajBxVHNmU1BTQWQ4dWFpRSJ9.eyJuYmYiOjE2MjA3NjkxMTAsImV4cCI6MTYyMzM2MTExMCwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODA4MSIsImNsaWVudF9pZCI6Im1jIiwic3ViIjoiQ0YxQjczMDYtOUM4Qy00REZGLUE2NzgtMTBDREJDMEYzRDMxIiwiYXV0aF90aW1lIjoxNjIwNzY5MTA5LCJpZHAiOiJsb2NhbCIsImlkZW50aXR5Ijoie1widXNlckdVSURcIjpcIkNGMUI3MzA2LTlDOEMtNERGRi1BNjc4LTEwQ0RCQzBGM0QzMVwiLFwidXNlcm5hbWVcIjpcImFkYW0uYnJvd25AZWR1Y2F0aW9ucGxhbm5lcmJjLmNhXCIsXCJyb290XCI6dHJ1ZSxcInVzZXJQZXJtc1wiOlt7XCJ0ZW5hbnRJRFwiOlwiMTk2RUUzNjMtQTVBMy00QzQ3LThGREItMkU4REE4REJFMkU5XCIsXCJwZXJtc1wiOlt7XCJjYXRlZ29yeVwiOlwiQU5ZXCIsXCJhY3Rpb25zXCI6W1wiQUxMXCJdfV19LHtcInRlbmFudElEXCI6XCIyRDAzRDY3Ny02RDY0LTRGMzYtQjA5OC05Q0E0ODdFM0I2RUFcIixcInBlcm1zXCI6W3tcImNhdGVnb3J5XCI6XCJBRE1cIixcImFjdGlvbnNcIjpbXCJSRUFEXCJdfV19LHtcInRlbmFudElEXCI6XCI0NDEwNTBDMS04ODM5LTRBRTktOTY5My03OTVFNEU0RkE4NzVcIixcInBlcm1zXCI6W119LHtcInRlbmFudElEXCI6XCI1MzlFMjQ3NS0wMjE1LTQ0QzMtQTREMC1FQTgwNkNGOUFCOUZcIixcInBlcm1zXCI6W3tcImNhdGVnb3J5XCI6XCJBTllcIixcImFjdGlvbnNcIjpbXCJBTExcIl19XX1dfSIsImp0aSI6IjI2NTE2MzAzOThGNjA3RjdENEE2NDYwNzQ2NEFENzMyIiwic2lkIjoiODNERjUzNTc2NUM2QzRDQzQ3ODUwNzgyQTE0QTdGQjgiLCJpYXQiOjE2MjA3NjkxMTAsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJlbWFpbCIsImVwYmNfaWRlbnRpdHkiLCJvZmZsaW5lX2FjY2VzcyJdLCJhbXIiOlsicHdkIl19.ydqtqCrEir97BYfr7Q_Dz_ubM9zDl3tbRB1YkNR2iVSBXKyGZnIKQFVoohW7b-fSZ2ute5_1n2t0xo91VzUupckruGE04zWQ_y2fWCexhZTEUNCLs9yQLHcluzbadMHMkwXqgqfQ2VVXImLbg8tpoDPJnGeGQQ0isK7eYslvZPTPhIHV1LIqhErAQplNTcAj12SPv2imN4KkAHjdg2_FtaM_XFNb5cVr_daQnwZsC_RgBRAYjWN3XbCDtRdNxnIrKO0Jg3c_SFVhV2A-EbieuRYZ5nEni3ETgpjY9UX7NK9tbEBfcj5qsoPgmFwE6Ppqfx59lrl414bYV3wN91nYA32lxBOJTLiCU-yevxV1Y76Fx-MVq0rV9VOJ2i_6N7hOOxXldae-iq7kvC7EdZTLdnp36KYZy2-U15_XQ9naaX_b9VCe5BOIjafSUn57C99OIgE-XIOYUf-0sZ-HpTO_RdK9yHiMqdadTnH6ceBrakjp-Es4YXwS-AdaW9CuwuEW8AO0FYYC8l-bzbDiUqN0quZ3yzbOVmDxAW1deFjGWAXuxxpolXwCuP4P6PWWOCXURGwhTxDUPwDJaIuJmSzIIJyCXQppbEHIAD9j4MazXqZhSOI0d1RPaROUC-O5ffrLg1m22dvX85nuy6-3WKaci4pCmfKv0z-vhSuCYzV3DHU"
	adamJWT = `{
		"nbf": 1620162215,
		"exp": 1622754215,
		"iss": "https://localhost:8081",
		"client_id": "mc",
		"sub": "CF1B7306-9C8C-4DFF-A678-10CDBC0F3D31",
		"auth_time": 1620161732,
		"idp": "local",
		"identity": "{\"userGUID\":\"CF1B7306-9C8C-4DFF-A678-10CDBC0F3D31\",\"username\":\"adam.brown@educationplannerbc.ca\",\"root\":true,\"userPerms\":[{\"tenantID\":\"196EE363-A5A3-4C47-8FDB-2E8DA8DBE2E9\",\"perms\":[{\"category\":\"ANY\",\"actions\":[\"ALL\"]}]},{\"tenantID\":\"2D03D677-6D64-4F36-B098-9CA487E3B6EA\",\"perms\":[{\"category\":\"ADM\",\"actions\":[\"READ\"]}]},{\"tenantID\":\"441050C1-8839-4AE9-9693-795E4E4FA875\",\"perms\":[]},{\"tenantID\":\"539E2475-0215-44C3-A4D0-EA806CF9AB9F\",\"perms\":[{\"category\":\"ANY\",\"actions\":[\"ALL\"]}]}]}",
		"jti": "125CDAD2FA10EDB6DB15737A4DD7A323",
		"sid": "DE77509D1ACFDDB8DF152FF70E708068",
		"iat": 1620162215,
		"scope": [
		  "openid",
		  "profile",
		  "email",
		  "epbc_identity",
		  "offline_access"
		],
		"amr": [
		  "pwd"
		]
	  }`
)

func init() {
	var err error
	publicKey, err = ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatal(err)
	}
	secret = []byte("RyxDWzqg8AaDAHxGt989tEPdfG42dr6e5QqCxJ4mwGKYavtLbj")
	// TODO	auth, err = NewAuth(jwtHeader, publicKey, secret, tokens, blocks)
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
		userGUID string
		username string
		root     bool
		tenantID string
	}

	tests := []struct {
		name  string
		args  args
		wants wants
	}{
		{
			"Adam claims",
			args{
				keyType:     "rsa",
				key:         publicKey,
				tokenString: adamTkn,
			},
			wants{
				"CF1B7306-9C8C-4DFF-A678-10CDBC0F3D31",
				"adam.brown@educationplannerbc.ca",
				true,
				"441050C1-8839-4AE9-9693-795E4E4FA875",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := auth.JWTIdentity(tt.args.tokenString)
			if err == nil {
				if identity.Root != tt.wants.root {
					t.Errorf("%s: identity.Root = %t, want %t", tt.name, identity.Root, tt.wants.root)
				}
				if *identity.Name != tt.wants.username {
					t.Errorf("%s: identity.Username = %s, want %s", tt.name, *identity.Name, tt.wants.username)
				}
			} else {
				t.Errorf("%s: %s", tt.name, err)
			}

		})
	}
}
