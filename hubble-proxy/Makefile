include ../Makefile.quiet
include ../Makefile.defs

TARGET=hubble-proxy
SOURCES := $(shell find . ../pkg/hubble \( -name '*.go' ! -name '*_test.go' \))


all: $(TARGET)

$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $(TARGET)
	strip $(TARGET)

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CONFDIR)/bash_completion.d
	./$(TARGET) completion bash > bash_autocomplete
	$(QUIET)$(INSTALL) -m 0644 -T bash_autocomplete $(DESTDIR)$(CONFDIR)/bash_completion.d/hubble-proxy

.PHONY: clean install
