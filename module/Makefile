# SPDX-License-Identifier: MIT

# Add compiler flag(s).
ccflags-y += -frecord-gcc-switches # Save all compile-time information
ccflags-y += -Wall -Werror -Wno-missing-braces -std=gnu11 -D_GNU_SOURCE # Forcing standard
ccflags-y += -O2 -DNDEBUG -mgeneral-regs-only -fno-tree-vectorize # FPU-transparent observer
ccflags-y += -I$(M)/include/uapi -I$(M)/include
ccflags-y +=
ldflags-y +=

# Add path(s) of external C source or static library file(s) to temporarily copy to the local build directory.
EXTERN-HEADERS := ../include
EXTERN-OBJS :=
EXTERN-SRCS :=

KBUILD_EXTRA_SYMBOLS +=

# DO NOT EDIT THE BELOW!

SHELL := /bin/bash

M ?= $(shell pwd)
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

PACKAGE_NAME := $(shell grep '^PACKAGE_NAME=' $(M)/dkms.conf | cut -d'=' -f2 | tr -d '"')
KCTRACE_VERSION ?= $(shell if [ -r "$(M)/../generate-version.sh" ]; then sh "$(M)/../generate-version.sh"; else printf '%s\n' unknown; fi)
PACKAGE_VERSION := $(KCTRACE_VERSION)
DKMS_SRC_DIR := /usr/src/$(PACKAGE_NAME)-$(PACKAGE_VERSION)
ccflags-y += -DKCTRACE_VERSION=\"$(PACKAGE_VERSION)\"
ifneq ($(KERNELRELEASE),)
KCTRACE_CONTRACT_HEX := $(shell cat "$(M)/include/kctrace/contract.sha256" 2>/dev/null)
ifneq ($(shell printf '%s\n' '$(KCTRACE_CONTRACT_HEX)' | grep -E '^[0-9a-f]{64}$$'),)
KCTRACE_CONTRACT_BYTES := $(shell printf '%s' '$(KCTRACE_CONTRACT_HEX)' | sed 's/../0x&,/g;s/,$$//')
ccflags-y += '-DKCTRACE_CONTRACT_HEX="$(KCTRACE_CONTRACT_HEX)"' '-DKCTRACE_CONTRACT_BYTES={$(KCTRACE_CONTRACT_BYTES)}'
endif
endif

EXTERN := $(EXTERN-HEADERS) $(EXTERN-OBJS) $(EXTERN-SRCS)

# These will be passed to the Makefile of the kernel source.
MY-SRCS += $(M)/core.c
MY-OBJS += $(MY-SRCS:.c=.o) $(M)/probe.o
obj-m += $(PACKAGE_NAME).o
$(PACKAGE_NAME)-objs += $(notdir $(MY-OBJS)) $(notdir $(EXTERN-OBJS))

.PHONY: all build contract copy_extern remove_extern install uninstall load unload clean distclean

all: build

copy_extern:
ifndef source_tree
	extern="$(EXTERN)"; \
	if [ -n "$$extern" ]; then \
		cp -rp $$extern $(M)/; \
	fi
else
	rsync -av $(source_tree)/$(PACKAGE_NAME)-$(PACKAGE_VERSION)/ $(M)/ --exclude=Makefile >/dev/null
endif
remove_extern:
ifndef source_tree
	rm -rf $(notdir $(EXTERN-OBJS))
endif

LLVM ?= $(shell grep -q '^#define CONFIG_CC_IS_GCC 1' $(KDIR)/include/generated/autoconf.h 2>/dev/null || echo 1)
CTRACE_LLVM ?= $(LLVM)
LLVM_OPT := LLVM=$(CTRACE_LLVM)

contract: copy_extern
	sh "$(M)/generate-contract.sh" "$(M)" "$(M)/include" "$(M)/include/kctrace/contract.sha256"

build: contract
	@set -e; \
    exit_code=0; \
    $(MAKE) -C $(KDIR) M=$(M) $(LLVM_OPT) KCTRACE_VERSION="$(PACKAGE_VERSION)" modules || exit_code=$$?; \
    $(MAKE) remove_extern; \
    if [ $$exit_code -ne 0 ]; then exit $$exit_code; fi; \
    ar -rcs $(PACKAGE_NAME).a $(MY-OBJS)

install: contract
	@set -e; \
	trap 'make remove_extern' EXIT; \
	if dkms status -m "$(PACKAGE_NAME)" -v "$(PACKAGE_VERSION)" 2>/dev/null | grep -Fq '$(PACKAGE_NAME)/$(PACKAGE_VERSION)'; then \
		dkms remove -m "$(PACKAGE_NAME)" -v "$(PACKAGE_VERSION)" --all; \
	fi; \
	rm -rf "$(DKMS_SRC_DIR)"; \
	install -d "$(DKMS_SRC_DIR)"; \
	for file in "$(M)/Makefile" "$(M)"/*.c "$(M)"/*.h "$(M)"/*.S "$(M)"/*.sh "$(M)"/*.rules $(addprefix $(M)/,$(notdir $(EXTERN))); do \
		[ -e "$$file" ] || continue; \
		case "$$file" in *.mod.c) continue ;; esac; \
		cp -a "$$file" "$(DKMS_SRC_DIR)/"; \
	done; \
	sed 's/^KCTRACE_VERSION=.*/KCTRACE_VERSION="$(KCTRACE_VERSION)"/' "$(M)/dkms.conf" > "$(DKMS_SRC_DIR)/dkms.conf"; \
	dkms add "$(DKMS_SRC_DIR)"; \
	CTRACE_LLVM="$(CTRACE_LLVM)" dkms build -m "$(PACKAGE_NAME)" -v "$(PACKAGE_VERSION)" -k "$(KVER)" --kernelsourcedir "$(KDIR)"; \
	CTRACE_LLVM="$(CTRACE_LLVM)" dkms install -m "$(PACKAGE_NAME)" -v "$(PACKAGE_VERSION)" -k "$(KVER)" --kernelsourcedir "$(KDIR)"; \
	for rules_file in "$(M)"/*.rules; do \
		[ -f "$$rules_file" ] || continue; \
		cp "$$rules_file" /etc/udev/rules.d/; \
	done

uninstall:
	@if dkms status -m "$(PACKAGE_NAME)" -v "$(PACKAGE_VERSION)" 2>/dev/null | grep -Fq '$(PACKAGE_NAME)/$(PACKAGE_VERSION)'; then \
		dkms remove -m "$(PACKAGE_NAME)" -v "$(PACKAGE_VERSION)" --all; \
	else \
		echo '$(PACKAGE_NAME)/$(PACKAGE_VERSION) is not registered with DKMS'; \
	fi
	rm -rf "$(DKMS_SRC_DIR)"
	@for rules_file in "$(M)"/*.rules; do \
		[ -f "$$rules_file" ] || continue; \
		rm -f "/etc/udev/rules.d/$${rules_file##*/}"; \
	done

load: all
	insmod $(PACKAGE_NAME).ko
unload:
	rmmod $(PACKAGE_NAME)

clean: TEMP_COMPILE_CMDS := $(shell mktemp)
clean:
	rm -f $(TEMP_COMPILE_CMDS)
	if [ -f compile_commands.json ]; then \
		cp compile_commands.json $(TEMP_COMPILE_CMDS) 2>/dev/null || :; \
	fi

	$(MAKE) -C $(KDIR) M=$(M) clean
	rm -rf $(notdir $(EXTERN-OBJS))

	if [ -f $(TEMP_COMPILE_CMDS) ]; then \
		cp $(TEMP_COMPILE_CMDS) compile_commands.json 2>/dev/null || :; \
		rm -f $(TEMP_COMPILE_CMDS); \
	fi
distclean:
	git clean -xddf
