package fauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"bitbucket.org/_metalogic_/httpsig"
	"bitbucket.org/_metalogic_/log"
)

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

// Verifying requires an application to use the pubKeyID to both retrieve the key needed for verification
// as well as determine the algorithm to use. Use a Verifier:
func verify(verifier httpsig.Verifier, tenantID string) bool {

	pubKeyID := verifier.KeyID()
	pubKey, found := pubKeys[pubKeyID]
	if !found {
		log.Errorf("public key not found for %s", pubKeyID)
		return false
	}

	if pubKeyID != tenantID {
		log.Errorf("public key ID %s is invalid for tenant %s", pubKeyID, tenantID)
		return false
	}

	log.Debugf("loading public key for %s", pubKeyID)

	rsa, err := loadPublicKey(pubKey)
	if err != nil {
		log.Errorf("failed to load public key %s", err)
		return false
	}

	// The verifier will verify the Digest in addition to the HTTP signature
	err = verifier.Verify(rsa, httpsig.RSA_SHA256)
	if err != nil {
		log.Errorf("signature verification failed: %s", err)
		return false
	}
	return true
}

func loadPublicKey(keyData []byte) (*rsa.PublicKey, error) {
	pem, _ := pem.Decode(keyData)
	if pem == nil {
		return nil, fmt.Errorf("failed to decode public key %s", string(keyData))
	}
	if pem.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("public key is of the wrong type: %s", pem.Type)
	}

	key, err := x509.ParsePKIXPublicKey(pem.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(*rsa.PublicKey), nil
}