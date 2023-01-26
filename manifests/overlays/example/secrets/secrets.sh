#!/bin/sh

# seal the PostgreSQL secrets
kubectl create --namespace postgres secret generic postgres-secrets-config --dry-run=client --from-env-file=postgres.env  --output json  | kubeseal > postgres-kubeseal.json

# seal the forward-auth secrets
kubectl create --namespace origin secret generic forward-auth-secrets-config --dry-run=client --from-env-file=keys.env  --output json  | kubeseal > forward-auth-kubeseal.json

cat idp.pub | kubectl create secret generic forward-auth-secrets-config --dry-run=client --from-file=idp_public_key=/dev/stdin -o json | kubeseal --merge-into forward-auth-kubeseal.json

echo -n https://dev-q84yaa6r.us.auth0.com/pem | kubectl create secret generic forward-auth-secrets-config --dry-run=client --from-file=idp_public_key_url=/dev/stdin -o json | kubeseal --merge-into forward-auth-kubeseal.json

