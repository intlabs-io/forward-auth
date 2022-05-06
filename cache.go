package fauth

// the public key for testSpecPrivateKeyPEM used by client
const spuzzumPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`

const spuzzumTenantID = "2D03D677-6D64-4F36-B098-9CA487E3B6EA"

// pubKeys is a map of keyIDs to their respective public keys
var pubKeys map[string][]byte

func init() {
	pubKeys = make(map[string][]byte)
	pubKeys[spuzzumTenantID] = []byte(spuzzumPublicKeyPEM)
}

func get(keyID string) (publicKey []byte, err error) {
	var found bool
	publicKey, found = pubKeys[keyID]
	if !found {

	}
	return publicKey, nil
}
