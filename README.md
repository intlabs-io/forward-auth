# Traefik Forward Auth Service

[Traefik](https://traefik.io) is an HTTP reverse proxy and load balancer. 

Forward-auth is an implementation of Traefik forward-auth middleware.
Traefik reads forward-auth configuration from labels defined on Docker containers. All requests for configured
containers are passed through forward-auth to evaluate access control rules against the request. Requests that
satisfy matching access control rules are forwarded to the configured Docker container; those that do not are
denied with HTTP forbidden status.

## Configuration

### Environment Variables

FORWARD_AUTH_DATA_DIR               | host directory containing access.json                 | /usr/local/etc/forward-auth
APIS_HOST                           | TODO                                                  | localhost
FORWARD_AUTH_STORAGE                | storage adapter type - one of file, mssql, mock       | file
JWT_HEADER_NAME                     | TODO                                                  | X-Jwt-Header
OPENAPI_BUILD_TEMPLATE              | TODO                                                  | "<pre>((Project))\n(version ((Version)), revision ((Revision)))\n of ((Built))</pre>\n\n"
RUN_MODE                            | run mode of forward - one of LIVE or TEST             | LIVE
TENANT_PARAM_NAME                   | path parameter name for tenant ID                     | :tenantID
TRACE_HEADER_NAME                   | header name for tracing                               | X-Trace-Header
USER_HEADER_NAME                    | header name for session user                          | X-User-Header
IDENTITY_PROVIDER_PUBLIC_KEY_URL    | URL to GET Identity Provider public key               | 
DB_PORT                             | datbase listen port                                   | 5432 (Postgres), 1433 (MSSql)
DB_HOST                             | database hostname                                     | postgres.postgres.svc.cluster.local (Postgres), mssql.mssql.svc.cluster.local (MSSql)
DB_USER                             | database access user
DB_PASSWORD                         | database access user password
SSL_MODE                            | enable SSL database connection                        | disable (Postgres)


## Build Docker Image

```
$ docker build -t metalogic/forward-auth .
```

