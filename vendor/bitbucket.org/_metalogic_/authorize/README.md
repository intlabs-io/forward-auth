# Authorization Library

The core authorization library used by bitbucket.org/_metalogic_/forward-auth.

## Configuration

### Environment Variables

AUTH_DATA_DIR                       | host directory containing access.json                 | /usr/local/etc/forward-auth
AUTH_STORAGE                        | storage adapter type - one of file, mssql, mock       | file
JWT_HEADER_NAME                     | TODO                                                  | X-Jwt-Header
TENANT_PARAM_NAME                   | path parameter name for tenant ID                     | :tenantID
TRACE_HEADER_NAME                   | header name for tracing                               | X-Trace-Header
USER_HEADER_NAME                    | header name for session user                          | X-User-Header
IDENTITY_PROVIDER_PUBLIC_KEY_URL    | URL to GET Identity Provider public key               | 
DB_PORT                             | datbase listen port                                   | 5432 (Postgres), 1433 (MSSql)
DB_HOST                             | database hostname                                     | postgres.postgres.svc.cluster.local (Postgres), mssql.mssql.svc.cluster.local (MSSql)
DB_USER                             | database access user
DB_PASSWORD                         | database access user password
SSL_MODE                            | enable SSL database connection                        | disable (Postgres)
