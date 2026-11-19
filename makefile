# ── pcapstat Makefile ─────────────────────────────────────────────────
# C11 build with libpcap, cairo, and libm.
# Output layout:  bin/  (executables)   build/{release,debug,asan,test}/  (*.o  *.d)

# ── Toolchain ────────────────────────────────────────────────────────
CC       := gcc
CSTD     := -std=c11 -D_DEFAULT_SOURCE
WARNINGS := -Wall -Wextra -Wpedantic -Wshadow
DEPFLAGS := -MMD -MP

PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS   := $(shell pkg-config --libs   libpcap 2>/dev/null || echo -lpcap)

CAIRO_CFLAGS := $(shell pkg-config --cflags cairo)
CAIRO_LIBS   := $(shell pkg-config --libs   cairo)

COMMON_CFLAGS := $(CSTD) $(WARNINGS) $(DEPFLAGS) $(PCAP_CFLAGS) $(CAIRO_CFLAGS)
LIBS          := $(PCAP_LIBS) $(CAIRO_LIBS) -lm

# ── Directories ──────────────────────────────────────────────────────
SRCDIR   := src
INCDIR   := include
TESTDIR  := tests
BINDIR   := bin
BUILDDIR := build

# Per-target build subdirectories (avoid object-file reuse across configs)
BUILD_REL   := $(BUILDDIR)/release
BUILD_DBG   := $(BUILDDIR)/debug
BUILD_ASAN  := $(BUILDDIR)/asan
BUILD_TEST  := $(BUILDDIR)/test

# ── Source lists ─────────────────────────────────────────────────────
SRCS     := $(wildcard $(SRCDIR)/*.c)
LIB_SRCS := $(filter-out $(SRCDIR)/main.c,$(SRCS))

TEST_SRCS := $(wildcard $(TESTDIR)/test_*.c)
TEST_BINS := $(patsubst $(TESTDIR)/%.c,$(BINDIR)/%,$(TEST_SRCS))

# Per-target object lists
REL_OBJS  := $(patsubst $(SRCDIR)/%.c,$(BUILD_REL)/%.o,$(SRCS))
DBG_OBJS  := $(patsubst $(SRCDIR)/%.c,$(BUILD_DBG)/%.o,$(SRCS))
ASAN_OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILD_ASAN)/%.o,$(SRCS))

TEST_LIB_OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILD_TEST)/%.o,$(LIB_SRCS))
TEST_T_OBJS   := $(patsubst $(TESTDIR)/%.c,$(BUILD_TEST)/%.o,$(TEST_SRCS))

ALL_DEPS := $(wildcard $(BUILDDIR)/*/*.d)

# ── Per-target flags ─────────────────────────────────────────────────
REL_CFLAGS  := $(COMMON_CFLAGS) -O2
DBG_CFLAGS  := $(COMMON_CFLAGS) -g -O0 -Werror
ASAN_CFLAGS := $(COMMON_CFLAGS) -g -O1 -Werror -fsanitize=address,undefined -fno-omit-frame-pointer
TEST_CFLAGS := $(COMMON_CFLAGS) -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer

ASAN_LDFLAGS := -fsanitize=address,undefined
TEST_LDFLAGS := -fsanitize=address,undefined

# ── Phony targets ───────────────────────────────────────────────────
.PHONY: all debug asan valgrind unit-test test clean gen-sample

# ── all (release) ────────────────────────────────────────────────────
all: $(BINDIR)/pcapstat

# ── debug ────────────────────────────────────────────────────────────
debug: $(BINDIR)/pcapstat-debug

# ── asan ─────────────────────────────────────────────────────────────
asan: $(BINDIR)/pcapstat-asan

# ── valgrind (build debug, run under valgrind) ───────────────────────
valgrind: $(BINDIR)/pcapstat-debug
	valgrind --leak-check=full --show-leak-kinds=definite,indirect \
	         --error-exitcode=1 $(BINDIR)/pcapstat-debug $(ARGS)

# ── unit-test ────────────────────────────────────────────────────────
unit-test: $(TEST_BINS)
	@echo "=== Running unit tests ==="
	@fail=0; \
	for t in $(TEST_BINS); do \
	    echo "--- $$t ---"; \
	    $$t || fail=1; \
	done; \
	exit $$fail

# ── test (integration: run_tests.sh) ────────────────────────────────
test: all debug asan unit-test
	@if [ -x $(TESTDIR)/run_tests.sh ]; then \
	    echo "=== Running integration tests ==="; \
	    $(TESTDIR)/run_tests.sh; \
	else \
	    echo "(no integration test script yet)"; \
	fi

# ── gen-sample (synthetic demo.pcap) ─────────────────────────────────
GEN_SRC := $(TESTDIR)/gen_demo_pcap.c
GEN_BIN := $(BINDIR)/gen_demo_pcap
SAMPLE  := samples/demo.pcap

gen-sample: $(SAMPLE)

$(SAMPLE): $(GEN_BIN) | samples
	./$(GEN_BIN)

$(GEN_BIN): $(GEN_SRC) | $(BINDIR)
	$(CC) $(ASAN_CFLAGS) -I$(INCDIR) $(ASAN_LDFLAGS) -o $@ $< $(PCAP_LIBS)

samples:
	mkdir -p samples

# ── clean ────────────────────────────────────────────────────────────
clean:
	rm -rf $(BINDIR) $(BUILDDIR)

# ── Link rules ───────────────────────────────────────────────────────
$(BINDIR)/pcapstat: $(REL_OBJS) | $(BINDIR)
	$(CC) -o $@ $^ $(LIBS)

$(BINDIR)/pcapstat-debug: $(DBG_OBJS) | $(BINDIR)
	$(CC) -o $@ $^ $(LIBS)

$(BINDIR)/pcapstat-asan: $(ASAN_OBJS) | $(BINDIR)
	$(CC) $(ASAN_LDFLAGS) -o $@ $^ $(LIBS)

$(BINDIR)/test_%: $(BUILD_TEST)/test_%.o $(TEST_LIB_OBJS) | $(BINDIR)
	$(CC) $(TEST_LDFLAGS) -o $@ $^ $(LIBS)

# ── Compile rules ────────────────────────────────────────────────────
$(BUILD_REL)/%.o: $(SRCDIR)/%.c | $(BUILD_REL)
	$(CC) $(REL_CFLAGS) -I$(INCDIR) -c -o $@ $<

$(BUILD_DBG)/%.o: $(SRCDIR)/%.c | $(BUILD_DBG)
	$(CC) $(DBG_CFLAGS) -I$(INCDIR) -c -o $@ $<

$(BUILD_ASAN)/%.o: $(SRCDIR)/%.c | $(BUILD_ASAN)
	$(CC) $(ASAN_CFLAGS) -I$(INCDIR) -c -o $@ $<

$(BUILD_TEST)/%.o: $(SRCDIR)/%.c | $(BUILD_TEST)
	$(CC) $(TEST_CFLAGS) -I$(INCDIR) -c -o $@ $<

$(BUILD_TEST)/%.o: $(TESTDIR)/%.c | $(BUILD_TEST)
	$(CC) $(TEST_CFLAGS) -I$(INCDIR) -c -o $@ $<

# ── Directory creation ───────────────────────────────────────────────
$(BINDIR) $(BUILD_REL) $(BUILD_DBG) $(BUILD_ASAN) $(BUILD_TEST):
	mkdir -p $@

# ── Auto-dependencies ────────────────────────────────────────────────
-include $(ALL_DEPS)
