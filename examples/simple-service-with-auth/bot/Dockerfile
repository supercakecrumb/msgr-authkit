FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
WORKDIR /src/examples/simple-service-with-auth
RUN if [ -d vendor ]; then \
      CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o /out/bot ./bot/cmd/bot; \
    else \
      go mod download && CGO_ENABLED=0 GOOS=linux go build -o /out/bot ./bot/cmd/bot; \
    fi

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/bot /usr/local/bin/bot
CMD ["bot"]
