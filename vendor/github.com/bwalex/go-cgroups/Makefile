GO?=go

SOURCEDIR=.

SOURCES := $(shell find $(SOURCEDIR) -name '*.go')

.PHONY: test
test: $(SOURCES)
	$(GO) test -v


.PHONY: benchmark
benchmark: $(SOURCES)
	$(GO) test -bench=.

.PHONY: clean
clean:
	rm -f $(PROG)
