CC          := gcc
APP_NAME    := pcapstat

SRC_DIR     := src
INC_DIR     := include
BUILD_DIR   := build

# Tryb kompilacji: release (domyślny), debug lub asan
MODE        ?= release
OBJ_DIR     := $(BUILD_DIR)/$(MODE)

ifeq ($(MODE),release)
	TARGET := $(APP_NAME)
else
	TARGET := $(APP_NAME)-$(MODE)
endif

SRCS        := $(wildcard $(SRC_DIR)/*.c)
OBJS        := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
DEPS        := $(OBJS:.o=.d)

# Automatyczne flagi z pkg-config (z fallbackiem na standardowe nazwy bibliotek)
CAIRO_CFLAGS := $(shell pkg-config --cflags cairo 2>/dev/null)
CAIRO_LIBS   := $(shell pkg-config --libs cairo 2>/dev/null || echo "-lcairo")
PCAP_CFLAGS  := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS    := $(shell pkg-config --libs libpcap 2>/dev/null || echo "-lpcap")

# -D_DEFAULT_SOURCE udostępnia typy BSD/POSIX wymagane przez libpcap i nagłówki sieciowe Linuksa
BASE_CFLAGS  := -std=c11 -D_DEFAULT_SOURCE -I$(INC_DIR) \
                -Wall -Wextra -Wpedantic -Wshadow \
                -MMD -MP $(PCAP_CFLAGS) $(CAIRO_CFLAGS)
LDFLAGS      := $(PCAP_LIBS) $(CAIRO_LIBS) -lm

ifeq ($(MODE),release)
	CFLAGS := $(BASE_CFLAGS) -O2
else ifeq ($(MODE),debug)
	CFLAGS := $(BASE_CFLAGS) -g3 -O0 -DDEBUG
else ifeq ($(MODE),asan)
	CFLAGS  := $(BASE_CFLAGS) -g3 -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -DDEBUG
	LDFLAGS += -fsanitize=address,undefined
else
	$(error Nieznany tryb MODE='$(MODE)'. Dostępne: release, debug, asan)
endif

.PHONY: all debug asan valgrind test clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $@

debug:
	$(MAKE) MODE=debug

asan:
	$(MAKE) MODE=asan

valgrind: debug
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
		./$(APP_NAME)-debug -i samples/demo.pcap -o out/

test: all
	@if [ -x tests/run_tests.sh ]; then \
		./tests/run_tests.sh; \
	else \
		echo "Brak wykonywalnego skryptu tests/run_tests.sh"; \
		exit 1; \
	fi

clean:
	rm -rf $(BUILD_DIR) $(APP_NAME) $(APP_NAME)-debug $(APP_NAME)-asan

-include $(DEPS)