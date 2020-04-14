include ../../Makefile.defs

TARGET=cilium-docker

all: $(TARGET)

SOURCES := $(shell find ../../api/v1 ../../common ../../pkg/client ../../pkg/endpoint driver . -name '*.go')

$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $(TARGET)

run:
	./cilium-docker -d

clean:
	@$(ECHO_CLEAN)
	$(QUIET)$(GO_CLEAN)
	-$(QUIET) rm -f $(TARGET)

install:
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
