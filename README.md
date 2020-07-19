# EPBC Traefik Forward Auth Service

Traefik is the EPBC gateway for all backend services. Backend services do not implement authorization logic. Rather Traefik ix configured to pass all HTTP requests through a forward auth service which is responsible for all authorization.

## Build Docker Image

```
$ docker build --no-cache -t epbc/forward-auth .
```

