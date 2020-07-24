FROM golang:1.14 as builder

ENV GOPRIVATE "bitbucket.org/_metalogic_/*"

COPY ./ /build

WORKDIR /build/cmd/server

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o forward-auth .

FROM metalogic/alpine:latest

RUN adduser -u 25010 -g 'Application Runner' -D runner

WORKDIR /home/runner

COPY --from=builder /build/cmd/server/forward-auth .
COPY --from=builder /build/cmd/server/mssql.yaml .
COPY --from=builder /build/cmd/server/file.toml .
COPY --from=builder /build/cmd/server/rules.json .
COPY --from=builder /build/docs docs

USER runner

CMD ["./forward-auth"]

HEALTHCHECK --interval=30s CMD /usr/local/bin/health http://localhost:8080/health

