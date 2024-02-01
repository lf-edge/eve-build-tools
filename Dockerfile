# Use an official Golang runtime as a parent image
FROM golang:1.21.6-alpine3.19 as builder

RUN apk --no-cache add make

# Copy the current directory contents into the container at /go/src/app
COPY . /go/src/app

# Set the working directory to /go/src/app
WORKDIR /go/src/app

# Compile the applications
RUN make tools OUTDIR=/usr/local/bin

# Deploy the application binaries into a lean image
FROM alpine:3.18
RUN apk --no-cache add ca-certificates=20230506-r0 \
  && update-ca-certificates

COPY --from=builder /usr/local/bin/* /usr/local/bin/

USER 1000

