FROM golang:1.21 as builder

ENV GOPRIVATE "bitbucket.org/_metalogic_/*"

COPY ./ /build

WORKDIR /build/cmd/server

RUN CGO_ENABLED=0 go build -o forward-auth .

FROM metalogic/alpine:3.15

RUN adduser -u 25000 -g 'Application Runner' -D runner

WORKDIR /home/runner

COPY --from=builder /build/cmd/server/forward-auth .
COPY --from=builder /build/docs docs

USER runner

CMD ["./forward-auth"]

HEALTHCHECK --interval=30s CMD /usr/local/bin/health http://localhost:8080/health

