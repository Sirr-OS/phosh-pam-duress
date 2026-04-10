# ──────────────────────────────────────────────────────────────────────────────
# sirr-pam-duress — PinePhone(Pro) / SirrOS (aarch64-linux-gnu)
# Cross-compiled from GitHub Actions on ubuntu-latest
# ──────────────────────────────────────────────────────────────────────────────

BIN_DIR  := bin
OBJ_DIR  := obj
SRC_DIR  := src

CC       := aarch64-linux-gnu-gcc
LD       := aarch64-linux-gnu-ld
STRIP    := aarch64-linux-gnu-strip

MULTIARCH   := aarch64-linux-gnu
SYSROOT     := /usr/$(MULTIARCH)

CFLAGS   := -O2 -fPIC -fno-stack-protector \
            -I$(SYSROOT)/include \
            -I/usr/include/$(MULTIARCH)

LDLIB    := -L$(SYSROOT)/lib \
            -L/usr/lib/$(MULTIARCH) \
            -lpam -lpam_misc -lssl -lcrypto -lc

LDFLAGS  := -x -shared

PAM_DIR      := /lib/security
BIN_INSTALL  := /usr/local/bin
HELPER_INSTALL := /usr/local/lib

# duress_helper.c is not included in the .so or the other binaries
SRCS = $(filter-out $(SRC_DIR)/duress_helper.c, $(wildcard $(SRC_DIR)/*.c))
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# ── Targets ───────────────────────────────────────────────────────────────────

.PHONY: all
all: $(BIN_DIR)/duress_sign $(BIN_DIR)/pam_test $(BIN_DIR)/pam_duress.so \
     $(BIN_DIR)/duress_helper

.PHONY: debug
debug: CFLAGS += -DDEBUG
debug: all

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/duress_sign: $(OBJ_DIR)/duress_sign.o $(OBJ_DIR)/util.o
	mkdir -p $(BIN_DIR)
	$(CC) -o $@ $^ $(LDLIB)

$(BIN_DIR)/pam_duress.so: $(OBJ_DIR)/duress.o $(OBJ_DIR)/util.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIB)

$(BIN_DIR)/pam_test: $(SRC_DIR)/pam_test.c
	mkdir -p $(BIN_DIR)
	$(CC) -o $@ $< $(LDLIB)

# duress_helper: standalone binary, statically linked with crypto
# The setuid bit is set during the install step, not here
$(BIN_DIR)/duress_helper: $(SRC_DIR)/duress_helper.c
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< \
	    -L$(SYSROOT)/lib \
	    -L/usr/lib/$(MULTIARCH) \
	    -lssl -lcrypto -lc

# ── Install (run on device) ───────────────────────────────────────────────────

.PHONY: install
install: all
	mkdir -p $(PAM_DIR)
	mkdir -p $(HELPER_INSTALL)
	$(STRIP) $(BIN_DIR)/*
	cp $(BIN_DIR)/pam_duress.so  $(PAM_DIR)/
	cp $(BIN_DIR)/duress_sign    $(BIN_INSTALL)/
	cp $(BIN_DIR)/pam_test       $(BIN_INSTALL)/
	cp $(BIN_DIR)/duress_helper  $(HELPER_INSTALL)/
	chown root:root              $(HELPER_INSTALL)/duress_helper
	chmod 4755                   $(HELPER_INSTALL)/duress_helper

.PHONY: uninstall
uninstall:
	rm -f $(PAM_DIR)/pam_duress.so
	rm -f $(BIN_INSTALL)/duress_sign
	rm -f $(BIN_INSTALL)/pam_test
	rm -f $(HELPER_INSTALL)/duress_helper

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)/ $(BIN_DIR)/ dist/
