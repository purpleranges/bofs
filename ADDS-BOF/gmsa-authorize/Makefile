CC     = x86_64-w64-mingw32-gcc
STRIP  = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../.. -Os -c -Wall -Wextra -fno-ident -DBOF

BOF_NAME = $(notdir $(CURDIR))
OUT_DIR  = ../_bin
OUT      = $(OUT_DIR)/$(BOF_NAME).x64.o

.PHONY: all clean

all: $(OUT)

$(OUT): src/$(BOF_NAME).c
	@mkdir -p $(OUT_DIR)
	@$(CC) $(CFLAGS) $< -o $@ && $(STRIP) $@ && echo '[+] $(BOF_NAME)' || echo '[!] $(BOF_NAME)'

clean:
	@rm -f $(OUT)
