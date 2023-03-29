# Metalogic access-apis service

## Build Docker Image

```
$ docker build -t metalogic/access-apis .
```

## Deploy to Kubernetes Cluster

From the manifests directory.

```
$ kustomize build overlay/your-custom-overlay > deploy
$ kubectl apply -f deploy
```

