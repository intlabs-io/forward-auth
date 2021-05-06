package fauth

import (
	"io/ioutil"
	"testing"

	"bitbucket.org/_metalogic_/log"
	jwt "github.com/dgrijalva/jwt-go"
)

var (
	publicKey []byte
	secret    = []byte("RyxDWzqg8AaDAHxGt989tEPdfG42dr6e5QqCxJ4mwGKYavtLbj")
	adamTkn   = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRFQjcxODhFMzhGOTgyNEY2M0QyQTRFQzdEMjNEMjAxREYyRTZBMjFSUzI1NiIsInR5cCI6ImF0K2p3dCIsIng1dCI6IlRyY1lqamo1Z2s5ajBxVHNmU1BTQWQ4dWFpRSJ9.eyJuYmYiOjE2MjAyNTQ4NzAsImV4cCI6MTYyMjg0Njg3MCwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODA4MSIsImNsaWVudF9pZCI6Im1jIiwic3ViIjoiQ0YxQjczMDYtOUM4Qy00REZGLUE2NzgtMTBDREJDMEYzRDMxIiwiYXV0aF90aW1lIjoxNjIwMjU0NTU2LCJpZHAiOiJsb2NhbCIsImlkZW50aXR5Ijoie1widXNlckdVSURcIjpcIkNGMUI3MzA2LTlDOEMtNERGRi1BNjc4LTEwQ0RCQzBGM0QzMVwiLFwidXNlcm5hbWVcIjpcImFkYW0uYnJvd25AZWR1Y2F0aW9ucGxhbm5lcmJjLmNhXCIsXCJyb290XCI6dHJ1ZSxcInVzZXJQZXJtc1wiOlt7XCJ0ZW5hbnRJRFwiOlwiMTk2RUUzNjMtQTVBMy00QzQ3LThGREItMkU4REE4REJFMkU5XCIsXCJwZXJtc1wiOlt7XCJjYXRlZ29yeVwiOlwiQU5ZXCIsXCJhY3Rpb25zXCI6W1wiQUxMXCJdfV19LHtcInRlbmFudElEXCI6XCIyRDAzRDY3Ny02RDY0LTRGMzYtQjA5OC05Q0E0ODdFM0I2RUFcIixcInBlcm1zXCI6W3tcImNhdGVnb3J5XCI6XCJBRE1cIixcImFjdGlvbnNcIjpbXCJSRUFEXCJdfV19LHtcInRlbmFudElEXCI6XCI0NDEwNTBDMS04ODM5LTRBRTktOTY5My03OTVFNEU0RkE4NzVcIixcInBlcm1zXCI6W119LHtcInRlbmFudElEXCI6XCI1MzlFMjQ3NS0wMjE1LTQ0QzMtQTREMC1FQTgwNkNGOUFCOUZcIixcInBlcm1zXCI6W3tcImNhdGVnb3J5XCI6XCJBTllcIixcImFjdGlvbnNcIjpbXCJBTExcIl19XX1dfSIsImp0aSI6IjM3RkE1RjIzRUIzRjJEOEVGMTUyNEExMEEzNjNFMDQ0Iiwic2lkIjoiNzUyNEI0QTkxRkUxNEMzRDI5MTlDMzVFRDgzQzk0NzUiLCJpYXQiOjE2MjAyNTQ4NzAsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJlbWFpbCIsImVwYmNfaWRlbnRpdHkiLCJvZmZsaW5lX2FjY2VzcyJdLCJhbXIiOlsicHdkIl19.QhGIVAT8Eb8GzNSykLJbj5SRypbpZeDgA5Gr0kja_sRRTEeOE9rLcdwKF853WFdqz4MzE-cdhndqoLjpxPyKhnM-VGJmjSPOlffYX8zJSEM3jPhzqxdHBr0d-g6lAJNr77PNq4_5CVfbo6BQ1NHQyjhxjNEmdnRiRnUNSjj2-4tBQQu5vyaKccKTm51n_eHetcNdoC5CeFlKwAJEs9zEsGSdGPmswtMVM7FEpd8B0TMFyrKihc9FJrN09Yoq3J6FSU1W7bPPkNWYU1irXNUGSTfkM2Wfx_PZcalk6XeQOsVBt0fj4ogSywyPiUXrc3RkfT8MbqQCpGuDNln8Dh6JO9HXWByj_gvPk4c_7N4TMcshw6EoGQjO42KADXGEmonAMZnnqPUioRpPJ4ai8gt2MpUIH-ZydRbcYE-hA1qktyJuqRetS8YwMN52dcS7emirX19-J8rbfJv7d7kOh17COSgI2zGV2d9UIl62YynDiKdJnyiGEgfxiKHhr8JfEqypVUSRWnplbqUTUOwAEDKxgHthXG8McgbHWe86QFTxrVQIXWUnaCDllw6sh8EUtMVQ0ElnEoliSVH4Buorr5-qg4cFEA-41Tcw4M-DieqO9JXxxaiV178_6MJR69VPLmKZKZHyCqTUg729THiCHlk8eka5RBuFBEx1KWR0S0MJFbU"
	adamJWT   = `{
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
	// use auth-api/v1/login to get rickyTkn string
	rickyTkn = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6eyJ1c2VyR1VJRCI6IjYwMENBOTI3LTVFMkItNDhCNC04Qzk1LUE1Qjg4MzlDM0E3RiIsInVzZXJuYW1lIjoicmlja3lAZWR1Y2F0aW9ucGxhbm5lcmJjLmNhIiwicm9vdCI6dHJ1ZSwidXNlclBlcm1zIjpbeyJ0ZW5hbnRJRCI6IjQ0MTA1MEMxLTg4MzktNEFFOS05NjkzLTc5NUU0RTRGQTg3NSIsInBlcm1zIjpbeyJjYXRlZ29yeSI6IlBST0ciLCJhY3Rpb25zIjpbIkNSRUFURSIsIkRFTEVURSIsIlJFQUQiLCJVUERBVEUiXX1dfV19LCJleHAiOjE2MjAyNjIxOTksImlhdCI6MTYyMDI2MDM5OSwiaXNzIjoiRWR1Y2F0aW9uUGxhbm5lckJDIn0.tcQ7kaWTNomeqtrw7rstO64xyGhWHR4BOS-v58LwlgA"
	rickyJWT = `{
		"nbf": 1619721524,
		"exp": 1619725124,
		"iss": "https://example.com",
		"client_id": "forward-auth",
		"sub": "CF1B7306-9C8C-4DFF-A678-10CDBC0F3D31",
		"auth_time": 1619721524,
		"idp": "local",
		"identity": {"userGUID":"CF1B7306-9C8C-4DFF-A678-10CDBC0F3D31",
		              "username":"ricky@educationplannerbc.ca",
					  "root":true,
					  "userPerms":[
						  {
							"tenantID": "441050C1-8839-4AE9-9693-795E4E4FA875",
							"perms": [
								{
									"category": "PROG",
									"actions": [
										"CREATE",
										"DELETE",
										"READ",
										"UPDATE"
									]
								}
							]
						}						  
						  }
					  ]},
		"jti": "2BC03C3941B5FF428A6F6FE7C1CE9255",
		"sid": "C0D2DB88F455BCA775AC79625E59947E",
		"iat": 1619721524,
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
	publicKey, err = ioutil.ReadFile("test/public.key")
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
		{
			"Ricky claims",
			args{
				keyType:     "secret",
				key:         secret,
				tokenString: rickyTkn,
			},
			wants{
				"600CA927-5E2B-48B4-8C95-A5B8839C3A7F",
				"ricky@educationplannerbc.ca",
				true,
				"441050C1-8839-4AE9-9693-795E4E4FA875",
			},
		},
	}

	for _, tt := range tests {
		switch tt.args.keyType {
		case "secret":
			t.Run(tt.name, func(t *testing.T) {
				identity, err := checkSecret(tt.args.key, tt.args.tokenString)
				if err != nil {
					t.Errorf("%s: %s", tt.name, err)
				}
				if identity.Root != tt.wants.root {
					t.Errorf("%s: identity.Root = %t, want %t", tt.name, identity.Root, tt.wants.root)
				}
			})
		case "rsa":
			t.Run(tt.name, func(t *testing.T) {
				rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(tt.args.key)
				if err != nil {
					t.Error(err)
				}
				identity, err := checkRSA(rsaKey, tt.args.tokenString)
				if err != nil {
					t.Errorf("%s: %s", tt.name, err)
				}
				if identity.Root != tt.wants.root {
					t.Errorf("%s: identity.Root = %t, want %t", tt.name, identity.Root, tt.wants.root)
				}
				if identity.Username != "adam.brown@educationplannerbc.ca" {
					t.Errorf("%s: identity.Username = %s, want %s", tt.name, identity.Username, tt.wants.username)
				}
			})
		}
	}
}
