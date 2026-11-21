# ── pcapstat Makefile ─────────────────────────────────────────────────
# C11 build with libpcap, cairo, and libm.
# Output layout:  bin/  (executables)   build/{release,debug,asan,test}/  (*.o  *.d)

# ── Toolchain ────────────────────────────────────────────────────────
# Overridable: `make CC=clang`, or CC from the environment. make predefines
# CC=cc, so `CC ?= gcc` would never take effect; only replace the default.
ifeq ($(origin CC),default)
CC := gcc
endif

# -Werror for the debug/asan/generator builds; a newer compiler with new
# warnings can still build everything with `make test WERROR=`.
WERROR ?= -Werror

CSTD     := -std=c11 -D_DEFAULT_SOURCE
WARNINGS := -Wall -Wextra -Wpedantic -Wshadow
DEPFLAGS := -MMD -MP

# Release hardening (fortify needs optimization, so release only).
# -U first: some distros predefine _FORTIFY_SOURCE (e.g. =3 on Ubuntu 24.04).
HARDEN_CFLAGS := -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong

# Sanitizers for asan, unit tests and the generator (compile and link).
# GCC's `undefined` group omits float-cast-overflow; -fno-sanitize-recover
# makes any UBSan finding abort the process instead of printing and
# continuing, so it fails the test instead of scrolling past.
SANITIZE := -fsanitize=address,undefined,float-cast-overflow -fno-sanitize-recover=all

PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS   := $(shell pkg-config --libs   libpcap 2>/dev/null || echo -lpcap)

CAIRO_CFLAGS := $(shell pkg-config --cflags cairo)
CAIRO_LIBS   := $(shell pkg-config --libs   cairo)

BASE_CFLAGS   := $(CSTD) $(WARNINGS) $(PCAP_CFLAGS) $(CAIRO_CFLAGS)
COMMON_CFLAGS := $(BASE_CFLAGS) $(DEPFLAGS)
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
REL_CFLAGS  := $(COMMON_CFLAGS) -O2 $(HARDEN_CFLAGS)
DBG_CFLAGS  := $(COMMON_CFLAGS) -g -O0 $(WERROR)
ASAN_CFLAGS := $(COMMON_CFLAGS) -g -O1 $(WERROR) $(SANITIZE) -fno-omit-frame-pointer
TEST_CFLAGS := $(COMMON_CFLAGS) -g -O1 $(WERROR) $(SANITIZE) -fno-omit-frame-pointer
# Generator: compiled and linked in one step straight into bin/, so no
# -MMD (it would leave a stray bin/gen_demo_pcap.d).
GEN_CFLAGS  := $(BASE_CFLAGS) -g -O1 $(WERROR) $(SANITIZE) -fno-omit-frame-pointer

ASAN_LDFLAGS := $(SANITIZE)
TEST_LDFLAGS := $(SANITIZE)
GEN_LDFLAGS  := $(SANITIZE)

# Runtime options for the unit tests: stack traces, stop at the first UBSan
# report, and no "Suppressions used" tables for the known fontconfig cache.
UNIT_UBSAN_OPTIONS := print_stacktrace=1:halt_on_error=1
UNIT_LSAN_OPTIONS  := suppressions=$(CURDIR)/$(TESTDIR)/lsan.supp:print_suppressions=0

# ── Phony targets ───────────────────────────────────────────────────
.PHONY: all debug asan valgrind unit-test test clean gen-sample fixtures

# Keep intermediate objects (build/test/*.o): otherwise make deletes them
# after linking the test binaries and `make test` ends with an `rm` line.
.SECONDARY:

# ── all (release) ────────────────────────────────────────────────────
all: $(BINDIR)/pcapstat

# ── debug ────────────────────────────────────────────────────────────
debug: $(BINDIR)/pcapstat-debug

# ── asan ─────────────────────────────────────────────────────────────
asan: $(BINDIR)/pcapstat-asan

# ── valgrind (build debug, run under valgrind) ───────────────────────
valgrind: $(BINDIR)/pcapstat-debug
	valgrind --leak-check=full --show-leak-kinds=definite,indirect \
	         --suppressions=$(TESTDIR)/valgrind.supp \
	         --error-exitcode=1 $(BINDIR)/pcapstat-debug $(ARGS)

# ── unit-test ────────────────────────────────────────────────────────
unit-test: $(TEST_BINS)
	@echo "=== Running unit tests ==="
	@export UBSAN_OPTIONS='$(UNIT_UBSAN_OPTIONS)'; \
	export LSAN_OPTIONS='$(UNIT_LSAN_OPTIONS)'; \
	fail=0; \
	for t in $(TEST_BINS); do \
	    echo "--- $$t ---"; \
	    $$t || fail=1; \
	done; \
	exit $$fail

# ── test (integration: run_tests.sh) ────────────────────────────────
# Run through bash unconditionally: does not depend on the exec bit, and a
# missing script fails the target instead of being skipped.
test: all debug asan unit-test fixtures
	@echo "=== Running integration tests ==="
	bash $(TESTDIR)/run_tests.sh

# ── gen-sample (synthetic demo.pcap) ─────────────────────────────────
GEN_SRC := $(TESTDIR)/gen_demo_pcap.c
GEN_BIN := $(BINDIR)/gen_demo_pcap
SAMPLE  := samples/demo.pcap

gen-sample: $(SAMPLE)

$(SAMPLE): $(GEN_BIN) | samples
	./$(GEN_BIN)

$(GEN_BIN): $(GEN_SRC) | $(BINDIR)
	$(CC) $(GEN_CFLAGS) -I$(INCDIR) $(GEN_LDFLAGS) -o $@ $< $(PCAP_LIBS)

samples:
	mkdir -p samples

# ── fixtures (edge-case captures for run_tests.sh) ───────────────────
# Only the generator is built here; run_tests.sh runs it into its own
# temporary directory, so no capture files land in the tree.
FIXTURE_SRC := $(TESTDIR)/gen_fixture_pcaps.c
FIXTURE_BIN := $(BINDIR)/gen_fixture_pcaps

fixtures: $(FIXTURE_BIN)

$(FIXTURE_BIN): $(FIXTURE_SRC) | $(BINDIR)
	$(CC) $(GEN_CFLAGS) -I$(INCDIR) $(GEN_LDFLAGS) -o $@ $< $(PCAP_LIBS)

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
