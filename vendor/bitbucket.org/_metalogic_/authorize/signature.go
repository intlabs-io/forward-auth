package authz

import (
	"crypto/rsa"

	"log/slog"

	"bitbucket.org/_metalogic_/httpsig"
)

// Verifying requires an application to use the keyID to both retrieve the key needed for verification
// as well as determine the algorithm to use.
// Public keys are stored in a cached key-value map tenantID => publicKey.
// The verifier extracts the public key ID from the signature on the request.
//
// An RSA public-private key pair is generated as follows:
//
//	$ openssl genrsa -out rsa.private 4096
//	$ openssl rsa -in rsaprivate -outrsa.public -pubout -outform PEM
func verify(verifier httpsig.Verifier, tenantID string, pubKeys map[string]*rsa.PublicKey) bool {

	keyID := verifier.KeyID()
	rsa, found := pubKeys[keyID]

	if !found {
		slog.Error("public key not found in store", "keyID", keyID)
		return false
	}

	if keyID != tenantID {
		slog.Error("public key ID is invalid for tenant", "keyID", keyID, "tenantID", tenantID)
		return false
	}

	// The verifier will verify the Digest in addition to the HTTP signature
	err := verifier.Verify(rsa, httpsig.RSA_SHA256)
	if err != nil {
		slog.Error("signature verification failed", "message", err)
		return false
	}
	return true
}
