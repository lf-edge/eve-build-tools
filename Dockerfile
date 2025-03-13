# Use an official Golang runtime as a parent image
FROM golang:1.23-alpine3.20 AS builder

RUN apk --no-cache add make

# Copy the current directory contents into the container at /go/src/app
COPY . /go/src/app

# Set the working directory to /go/src/app
WORKDIR /go/src/app

# Compile the applications
RUN make tools OUTDIR=/usr/local/bin

# Deploy the application binaries into a lean image
FROM alpine:3.20
# hadolint ignore=DL3018
RUN apk --no-cache add ca-certificates \
  && update-ca-certificates

COPY --from=builder /usr/local/bin/* /usr/local/bin/

USER 1000

