FROM golang:1.23-alpine AS build
WORKDIR /src
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/control-plane ./cmd/control-plane

FROM alpine:3.21
RUN adduser -D -H -u 10001 app
COPY --from=build /out/control-plane /usr/local/bin/control-plane
USER app
EXPOSE 8080
ENTRYPOINT ["control-plane"]
