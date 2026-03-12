FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
WORKDIR /src/examples/simple-service-with-auth
RUN if [ -d vendor ]; then \
      CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o /out/web ./web/cmd/web; \
    else \
      go mod download && CGO_ENABLED=0 GOOS=linux go build -o /out/web ./web/cmd/web; \
    fi

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
COPY --from=build /out/web /usr/local/bin/web
CMD ["web"]
