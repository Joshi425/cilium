include ../../Makefile.defs

all: cilium-cni

TARGET=cilium-cni

clean:
	@$(ECHO_CLEAN)
	$(QUIET)$(GO_CLEAN)
	-$(QUIET)rm -f $(TARGET)

SOURCES := $(shell find ../../api/v1/models ../../common ../../pkg/client ../../pkg/endpoint . -name '*.go')

$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	# Compile without cgo to allow use of cilium-cni on non-glibc platforms - see GH-5055
	$(QUIET)$(GO_BUILD) -o $(TARGET)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CNICONFDIR)
	$(QUIET)$(INSTALL) -m 0644 05-cilium-cni.conf $(DESTDIR)$(CNICONFDIR)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CNIBINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(CNIBINDIR)
