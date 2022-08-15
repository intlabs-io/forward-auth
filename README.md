# Traefik Forward Auth Service

[Traefik](https://traefik.io) is an HTTP reverse proxy and load balancer. 

Forward-auth is an implementation of Traefik forward-auth middleware.
Traefik reads forward-auth configuration from labels defined on Docker containers. All requests for configured
containers are passed through forward-auth to evaluate access control rules against the request. Requests that
satisfy matching access control rules are forwarded to the configured Docker container; those that do not are
denied with HTTP forbidden status.


## Build Docker Image

```
$ docker build -t metalogic/forward-auth .
```

