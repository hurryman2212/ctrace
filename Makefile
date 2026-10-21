# SPDX-License-Identifier: MIT

ifdef VERBOSE
NINJAFLAGS := -v
endif

.PHONY: all %
all:
	@ninja $(NINJAFLAGS)
%:
	@ninja $@ $(NINJAFLAGS)

distclean:
	git clean -xdf
