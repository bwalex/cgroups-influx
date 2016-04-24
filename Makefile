GO?=go

PROG=cgroups-influx
SOURCEDIR=.

SOURCES := $(shell find $(SOURCEDIR) -name '*.go')

$(PROG): $(SOURCES)
	$(GO) build -o $@

.PHONY: clean
clean:
	rm -f $(PROG)
