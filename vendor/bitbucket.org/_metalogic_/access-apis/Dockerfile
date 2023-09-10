FROM golang:1.21 as builder

COPY ./ /build

WORKDIR /build/cmd/server

RUN CGO_ENABLED=0 go build -o access-apis .

FROM metalogic/alpine:latest

RUN adduser -u 25010 -g 'Metalogic Application Owner' -D runner

WORKDIR /home/runner

COPY --from=builder /build/cmd/server/access-apis .
COPY --from=builder /build/docs docs 

USER runner

CMD ["./access-apis"]

# HEALTHCHECK --interval=30s CMD /usr/local/bin/health http://localhost:8080/${ACCESS_APIS_BASE}/health
