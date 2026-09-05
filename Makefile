# Auto-discovers every BOF folder (any subdirectory that has its own
# Makefile). Add a new BOF: drop a folder with a Makefile using the same
# template as the existing ones. No edit here required.

BOF_DIRS := $(patsubst %/Makefile,%,$(wildcard */*/Makefile))

.PHONY: all clean $(BOF_DIRS)

all: $(BOF_DIRS)

$(BOF_DIRS):
	@$(MAKE) --no-print-directory -C $@

clean:
	@for d in $(BOF_DIRS); do $(MAKE) --no-print-directory -C $$d clean; done
	@rm -rf */_bin
