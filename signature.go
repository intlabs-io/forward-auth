package fauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"bitbucket.org/_metalogic_/httpsig"
	"bitbucket.org/_metalogic_/log"
)

// Verifying requires an application to use the pubKeyID to both retrieve the key needed for verification
// as well as determine the algorithm to use. Public keys are stored in a cached key-value map
// tenantID => publicKey; the verifier extracts the public key ID fro the signature on the request
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
