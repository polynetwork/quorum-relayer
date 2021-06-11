FROM golang:1.14

ENV GO111MODULE=on \
    GOPROXY=direct \
    GIN_MODE=release

WORKDIR /app

COPY . .

RUN go build -o relayer main.go

ENTRYPOINT ["./relayer"]