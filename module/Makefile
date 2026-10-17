# SPDX-License-Identifier: MIT
KERNELRELEASE ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KERNELRELEASE)/build
MODULE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: all modules clean dkms-source
all: modules
modules:
	$(MAKE) -C "$(KDIR)" M="$(MODULE_DIR)" modules
clean:
	$(MAKE) -C "$(KDIR)" M="$(MODULE_DIR)" clean

# Explicit staging only; no privileged installation or DKMS registration.
dkms-source:
	@test -n "$(DKMS_SOURCE_DIR)" || { \
		echo "DKMS_SOURCE_DIR must name the package source directory" >&2; \
		exit 1; \
	}
	install -d "$(DKMS_SOURCE_DIR)/module" "$(DKMS_SOURCE_DIR)/include/uapi"
	install -m 644 "$(MODULE_DIR)/core.c" "$(MODULE_DIR)/probe.S" \
		"$(MODULE_DIR)/probe.h" "$(MODULE_DIR)/Kbuild" \
		"$(MODULE_DIR)/Makefile" "$(MODULE_DIR)/dkms.conf" \
		"$(DKMS_SOURCE_DIR)/module/"
	install -m 644 "$(MODULE_DIR)/../include/uapi/kctrace.h" \
		"$(DKMS_SOURCE_DIR)/include/uapi/"
	install -m 644 "$(MODULE_DIR)/../include/kctrace_policy.h" \
		"$(MODULE_DIR)/../include/kctrace_execution.h" \
		"$(MODULE_DIR)/../include/kctrace_interrupt.h" \
		"$(DKMS_SOURCE_DIR)/include/"
	install -m 644 "$(MODULE_DIR)/dkms.conf" "$(DKMS_SOURCE_DIR)/dkms.conf"
