#!/bin/sh

if [ $# != 1 ]; then
  echo usage: secrets.sh namespace
  exit 1
fi

namespace=$1

# seal the PostgreSQL secrets
kubectl create --namespace postgres secret generic auth-database-secrets --dry-run=client --from-env-file=database.env  --output json  | kubeseal > kubeseal-auth-database.json

# seal the forward-auth secrets
kubectl create --namespace $namespace secret generic forward-auth-secrets --dry-run=client --from-env-file=forward-auth-keys.env  --output json  | kubeseal > kubeseal-forward-auth.json

# seal identity provider public key
cat idp.pub | kubectl create --namespace $namespace secret generic forward-auth-secrets --dry-run=client --from-file=idp_public_key=/dev/stdin -o json | kubeseal --merge-into kubeseal-forward-auth.json

# seal identify provider public key URL
echo -n https://dev-q84yaa6r.us.auth0.com/pem | kubectl create --namespace $namespace secret generic forward-auth-secrets --dry-run=client --from-file=idp_public_key_url=/dev/stdin -o json | kubeseal --merge-into kubeseal-forward-auth.json

