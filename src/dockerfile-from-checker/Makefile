OUTDIR ?= bin
OUTFILE ?= $(OUTDIR)/dockerfile-from-checker

.PHONY: build test

build: $(OUTFILE)

$(OUTFILE): $(OUTDIR)
	go build -o $@ .

$(OUTDIR):
	mkdir -p $@

test:
	go test -v ./...

