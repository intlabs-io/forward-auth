package fauth

import (
	"crypto/rsa"

	"bitbucket.org/_metalogic_/httpsig"
	"bitbucket.org/_metalogic_/log"
)

// Verifying requires an application to use the keyID to both retrieve the key needed for verification
// as well as determine the algorithm to use.
// Public keys are stored in a cached key-value map tenantID => publicKey.
// The verifier extracts the public key ID from the signature on the request.
//
// An RSA public-private key pair is generated as follows:
//  $ openssl genrsa -out rsa.private 4096
//  $ openssl rsa -in rsaprivate -outrsa.public -pubout -outform PEM
func verify(verifier httpsig.Verifier, tenantID string, pubKeys map[string]*rsa.PublicKey) bool {

	keyID := verifier.KeyID()
	rsa, found := pubKeys[keyID]

	if !found {
		log.Errorf("public key not found in store for %s", keyID)
		return false
	}

	if keyID != tenantID {
		log.Errorf("public key ID %s is invalid for tenant %s", keyID, tenantID)
		return false
	}

	// The verifier will verify the Digest in addition to the HTTP signature
	err := verifier.Verify(rsa, httpsig.RSA_SHA256)
	if err != nil {
		log.Errorf("signature verification failed: %s", err)
		return false
	}
	return true
}
