FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o api .

FROM alpine:3.14
WORKDIR /app
# Running as root — vulnerable container config
USER root
COPY --from=builder /app/api .
EXPOSE 8080
CMD ["./api"]
