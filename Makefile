CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -Ilibs -Isrc
LDFLAGS = -lssl -lcrypto -largon2

BUILD   = build
TARGET  = $(BUILD)/pmanager

LIB_SRC = libs/crypto.c
APP_SRC = src/main.c src/vault.c

LIB_OBJ = $(patsubst libs/%.c, $(BUILD)/libs/%.o, $(LIB_SRC))
APP_OBJ = $(patsubst src/%.c,  $(BUILD)/src/%.o,  $(APP_SRC))
ALL_OBJ = $(LIB_OBJ) $(APP_OBJ)

all: $(TARGET)

$(TARGET): $(ALL_OBJ)
	$(CC) $(ALL_OBJ) -o $@ $(LDFLAGS)

$(BUILD)/libs/%.o: libs/%.c
	@mkdir -p $(BUILD)/libs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/src/%.o: src/%.c
	@mkdir -p $(BUILD)/src
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean
