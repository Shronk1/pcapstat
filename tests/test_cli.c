/**
 * @file test_cli.c
 * @brief Unit tests for the CLI argument parser (cli.h / cli.c).
 *
 * Tests cover: single/multiple -i flags, positional args, mixed inputs,
 * -o override, default output dir, --portscan-threshold (valid + invalid),
 * --help, --version, --verbose, unknown options, and cli_validate_and_prepare
 * (no inputs, unreadable file, successful creation of output directory).
 */

#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Minimal test harness ────────────────────────────────────────────── */

static int g_tests_run;
static int g_tests_passed;

#define TEST_ASSERT(cond)                                               \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "    ASSERT FAILED: %s  (%s:%d)\n",        \
                    #cond, __FILE__, __LINE__);                         \
            return 0;                                                   \
        }                                                               \
    } while (0)

#define RUN_TEST(fn)                                                    \
    do {                                                                \
        g_tests_run++;                                                  \
        printf("  %-44s ", #fn);                                        \
        fflush(stdout);                                                 \
        if (fn()) { g_tests_passed++; printf("PASS\n"); }              \
        else      { printf("FAIL\n"); }                                 \
    } while (0)

/* ── Parse tests ─────────────────────────────────────────────────────── */

static int test_help_short(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "-h", NULL };
    TEST_ASSERT(cli_parse(2, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.show_help == true);
    cli_free(&cfg);
    return 1;
}

static int test_help_long(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "--help", NULL };
    TEST_ASSERT(cli_parse(2, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.show_help == true);
    cli_free(&cfg);
    return 1;
}

static int test_version_short(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "-V", NULL };
    TEST_ASSERT(cli_parse(2, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.show_version == true);
    cli_free(&cfg);
    return 1;
}

static int test_version_long(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "--version", NULL };
    TEST_ASSERT(cli_parse(2, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.show_version == true);
    cli_free(&cfg);
    return 1;
}

static int test_single_input(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "-i", "a.pcap", NULL };
    TEST_ASSERT(cli_parse(3, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.input_count == 1);
    TEST_ASSERT(strcmp(cfg.input_files[0], "a.pcap") == 0);
    cli_free(&cfg);
    return 1;
}

static int test_multiple_inputs(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "-i", "a.pcap", "-i", "b.pcap",
                     "-i", "c.pcap", NULL };
    TEST_ASSERT(cli_parse(7, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.input_count == 3);
    TEST_ASSERT(strcmp(cfg.input_files[0], "a.pcap") == 0);
    TEST_ASSERT(strcmp(cfg.input_files[1], "b.pcap") == 0);
    TEST_ASSERT(strcmp(cfg.input_files[2], "c.pcap") == 0);
    cli_free(&cfg);
    return 1;
}

static int test_positional_args(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "x.pcap", "y.pcap", NULL };
    TEST_ASSERT(cli_parse(3, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.input_count == 2);
    TEST_ASSERT(strcmp(cfg.input_files[0], "x.pcap") == 0);
    TEST_ASSERT(strcmp(cfg.input_files[1], "y.pcap") == 0);
    cli_free(&cfg);
    return 1;
}

static int test_mixed_inputs(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "-i", "a.pcap", "b.pcap", NULL };
    TEST_ASSERT(cli_parse(4, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.input_count == 2);
    TEST_ASSERT(strcmp(cfg.input_files[0], "a.pcap") == 0);
    TEST_ASSERT(strcmp(cfg.input_files[1], "b.pcap") == 0);
    cli_free(&cfg);
    return 1;
}

static int test_output_dir(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "-i", "f.pcap", "-o", "/tmp/myout", NULL };
    TEST_ASSERT(cli_parse(5, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(strcmp(cfg.output_dir, "/tmp/myout") == 0);
    cli_free(&cfg);
    return 1;
}

static int test_output_dir_long(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "--output", "/tmp/x", "-i", "f.pcap", NULL };
    TEST_ASSERT(cli_parse(5, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(strcmp(cfg.output_dir, "/tmp/x") == 0);
    cli_free(&cfg);
    return 1;
}

static int test_default_output_dir(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "-i", "f.pcap", NULL };
    TEST_ASSERT(cli_parse(3, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(strcmp(cfg.output_dir, "./pcapstat_out") == 0);
    cli_free(&cfg);
    return 1;
}

static int test_portscan_threshold(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "--portscan-threshold", "50",
                     "-i", "f.pcap", NULL };
    TEST_ASSERT(cli_parse(5, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.thresholds.portscan_threshold == 50);
    cli_free(&cfg);
    return 1;
}

static int test_portscan_threshold_invalid_text(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "--portscan-threshold", "abc", NULL };
    TEST_ASSERT(cli_parse(3, argv, &cfg) == PCAPSTAT_ERR_ARGS);
    cli_free(&cfg);
    return 1;
}

static int test_portscan_threshold_zero(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "--portscan-threshold", "0", NULL };
    TEST_ASSERT(cli_parse(3, argv, &cfg) == PCAPSTAT_ERR_ARGS);
    cli_free(&cfg);
    return 1;
}

static int test_portscan_threshold_negative(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "--portscan-threshold=-5", NULL };
    TEST_ASSERT(cli_parse(2, argv, &cfg) == PCAPSTAT_ERR_ARGS);
    cli_free(&cfg);
    return 1;
}

static int test_unknown_option(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "--nonexistent", NULL };
    TEST_ASSERT(cli_parse(2, argv, &cfg) == PCAPSTAT_ERR_ARGS);
    cli_free(&cfg);
    return 1;
}

static int test_verbose(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "-v", "-i", "f.pcap", NULL };
    TEST_ASSERT(cli_parse(4, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.verbose == true);
    cli_free(&cfg);
    return 1;
}

static int test_default_thresholds(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "-i", "f.pcap", NULL };
    TEST_ASSERT(cli_parse(3, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.thresholds.portscan_threshold == DEFAULT_PORTSCAN_THRESHOLD);
    TEST_ASSERT(cfg.thresholds.syn_flood_min == DEFAULT_SYN_FLOOD_MIN);
    TEST_ASSERT(cfg.thresholds.syn_ratio == DEFAULT_SYN_RATIO);
    TEST_ASSERT(cfg.thresholds.retrans_pct == DEFAULT_RETRANS_PCT);
    TEST_ASSERT(cfg.thresholds.rst_pct == DEFAULT_RST_PCT);
    TEST_ASSERT(cfg.thresholds.udp_burst_mult == DEFAULT_UDP_BURST_MULT);
    TEST_ASSERT(cfg.thresholds.udp_burst_min == DEFAULT_UDP_BURST_MIN);
    cli_free(&cfg);
    return 1;
}

static int test_long_input(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "--input", "long.pcap", NULL };
    TEST_ASSERT(cli_parse(3, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cfg.input_count == 1);
    TEST_ASSERT(strcmp(cfg.input_files[0], "long.pcap") == 0);
    cli_free(&cfg);
    return 1;
}

/* ── Validation tests ────────────────────────────────────────────────── */

static int test_validate_no_inputs(void)
{
    cli_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* No input files, so validation should fail. */
    TEST_ASSERT(cli_validate_and_prepare(&cfg) == PCAPSTAT_ERR_ARGS);
    return 1;
}

static int test_validate_bad_file(void)
{
    cli_config_t cfg;
    char *argv[] = { "pcapstat", "-i",
                     "/tmp/__pcapstat_nonexistent_31415926__.pcap", NULL };
    TEST_ASSERT(cli_parse(3, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cli_validate_and_prepare(&cfg) == PCAPSTAT_ERR_ARGS);
    cli_free(&cfg);
    return 1;
}

static int test_validate_success(void)
{
    cli_config_t cfg;
    /* /dev/null is always readable on Linux. */
    char *argv[] = { "pcapstat", "-i", "/dev/null",
                     "-o", "/tmp/pcapstat_test_cli", NULL };
    TEST_ASSERT(cli_parse(5, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cli_validate_and_prepare(&cfg) == PCAPSTAT_OK);
    /* Clean up the directory we just created. */
    rmdir("/tmp/pcapstat_test_cli");
    cli_free(&cfg);
    return 1;
}

static int test_validate_existing_output_dir(void)
{
    cli_config_t cfg;
    /* /tmp always exists — mkdir should tolerate EEXIST. */
    char *argv[] = { "pcapstat", "-i", "/dev/null", "-o", "/tmp", NULL };
    TEST_ASSERT(cli_parse(5, argv, &cfg) == PCAPSTAT_OK);
    TEST_ASSERT(cli_validate_and_prepare(&cfg) == PCAPSTAT_OK);
    cli_free(&cfg);
    return 1;
}

/* ── Print-usage smoke test ──────────────────────────────────────────── */

static int test_print_usage(void)
{
    /* Just verify it doesn't crash; output goes to /dev/null. */
    FILE *devnull = fopen("/dev/null", "w");
    TEST_ASSERT(devnull != NULL);
    cli_print_usage(devnull, "pcapstat");
    fclose(devnull);
    return 1;
}

/* ── cli_free on zeroed struct ───────────────────────────────────────── */

static int test_free_zeroed(void)
{
    cli_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cli_free(&cfg);   /* must not crash */
    return 1;
}

static int test_free_null(void)
{
    cli_free(NULL);    /* must not crash */
    return 1;
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== test_cli ===\n");

    /* Parse tests */
    RUN_TEST(test_help_short);
    RUN_TEST(test_help_long);
    RUN_TEST(test_version_short);
    RUN_TEST(test_version_long);
    RUN_TEST(test_single_input);
    RUN_TEST(test_multiple_inputs);
    RUN_TEST(test_positional_args);
    RUN_TEST(test_mixed_inputs);
    RUN_TEST(test_long_input);
    RUN_TEST(test_output_dir);
    RUN_TEST(test_output_dir_long);
    RUN_TEST(test_default_output_dir);
    RUN_TEST(test_portscan_threshold);
    RUN_TEST(test_portscan_threshold_invalid_text);
    RUN_TEST(test_portscan_threshold_zero);
    RUN_TEST(test_portscan_threshold_negative);
    RUN_TEST(test_unknown_option);
    RUN_TEST(test_verbose);
    RUN_TEST(test_default_thresholds);

    /* Validation tests */
    RUN_TEST(test_validate_no_inputs);
    RUN_TEST(test_validate_bad_file);
    RUN_TEST(test_validate_success);
    RUN_TEST(test_validate_existing_output_dir);

    /* Usage / free tests */
    RUN_TEST(test_print_usage);
    RUN_TEST(test_free_zeroed);
    RUN_TEST(test_free_null);

    printf("\nResults: %d/%d passed\n", g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? EXIT_SUCCESS : EXIT_FAILURE;
}
