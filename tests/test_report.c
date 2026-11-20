/**
 * @file test_report.c
 * @brief Unit and integration tests for multi-page PDF report generation (TASK-10).
 */

#include "anomaly.h"
#include "cli.h"
#include "common.h"
#include "parser.h"
#include "report.h"
#include "stats.h"

#include <cairo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(c)                                                               \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__,   \
                    #c);                                                       \
            abort();                                                           \
        }                                                                      \
    } while (0)

#define RUN(t)                                                                 \
    do {                                                                       \
        printf("  %s...\n", #t);                                               \
        t();                                                                   \
        printf("    PASS\n");                                                  \
    } while (0)

/**
 * @brief Verify that a file exists, is non-empty, begins with "%PDF-",
 *        and ends with the standard "%%EOF" marker.
 */
static void verify_pdf_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    CHECK(f != NULL);

    int seek_rc = fseek(f, 0, SEEK_END);
    CHECK(seek_rc == 0);

    long sz = ftell(f);
    CHECK(sz > 500); /* A valid 4-page PDF with charts is several KB */

    seek_rc = fseek(f, 0, SEEK_SET);
    CHECK(seek_rc == 0);

    char header[5];
    size_t n = fread(header, 1, 5, f);
    CHECK(n == 5);
    CHECK(memcmp(header, "%PDF-", 5) == 0);

    /* Check for %%EOF marker near the end of the file */
    long tail_sz = (sz < 1024) ? sz : 1024;
    seek_rc = fseek(f, -tail_sz, SEEK_END);
    CHECK(seek_rc == 0);

    char tail_buf[1024];
    size_t tn = fread(tail_buf, 1, (size_t)tail_sz, f);
    CHECK(tn == (size_t)tail_sz);
    fclose(f);

    CHECK(memmem(tail_buf, (size_t)tail_sz, "%%EOF", 5) != NULL);
}

static void test_null_and_invalid_args(void)
{
    cli_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);

    anomaly_list_t anomalies;
    CHECK(anomaly_list_init(&anomalies) == PCAPSTAT_OK);

    /* NULL cfg, stats, anomalies, or pdf_path */
    CHECK(report_generate(NULL, &stats, &anomalies, "/tmp/test.pdf") == PCAPSTAT_ERR_ARGS);
    CHECK(report_generate(&cfg, NULL, &anomalies, "/tmp/test.pdf") == PCAPSTAT_ERR_ARGS);
    CHECK(report_generate(&cfg, &stats, NULL, "/tmp/test.pdf") == PCAPSTAT_ERR_ARGS);
    CHECK(report_generate(&cfg, &stats, &anomalies, NULL) == PCAPSTAT_ERR_ARGS);
    CHECK(report_generate(&cfg, &stats, &anomalies, "") == PCAPSTAT_ERR_ARGS);

    /* Non-existent directory should return PCAPSTAT_ERR_IO */
    CHECK(report_generate(&cfg, &stats, &anomalies,
                          "/nonexistent_dir_pcapstat_314159/report.pdf") == PCAPSTAT_ERR_IO);

    anomaly_list_free(&anomalies);
    stats_free(&stats);
}

static void test_empty_stats_report(void)
{
    cli_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);

    anomaly_list_t anomalies;
    CHECK(anomaly_list_init(&anomalies) == PCAPSTAT_OK);

    const char *out_pdf = "/tmp/test_report_empty.pdf";
    unlink(out_pdf);

    int rc = report_generate(&cfg, &stats, &anomalies, out_pdf);
    CHECK(rc == PCAPSTAT_OK);

    verify_pdf_file(out_pdf);
    unlink(out_pdf);

    anomaly_list_free(&anomalies);
    stats_free(&stats);
}

static void test_demo_pcap_report(void)
{
    /* Verify demo.pcap exists */
    FILE *f = fopen("samples/demo.pcap", "rb");
    CHECK(f != NULL);
    fclose(f);

    /* Prepare CLI config */
    cli_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    char *inputs[1] = {"samples/demo.pcap"};
    cfg.input_files = inputs;
    cfg.input_count = 1;

    /* Parse demo.pcap and collect statistics */
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    int parse_rc = parser_process_file("samples/demo.pcap", stats_packet_cb, &stats);
    CHECK(parse_rc == PCAPSTAT_OK);
    stats.files_processed = 1;
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);

    /* Run anomaly detection */
    anomaly_list_t anomalies;
    CHECK(anomaly_list_init(&anomalies) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&stats, NULL, &anomalies) == PCAPSTAT_OK);
    CHECK(anomalies.count > 0);

    /* Generate report.pdf in working directory */
    const char *out_pdf = "report.pdf";
    unlink(out_pdf);

    int rc = report_generate(&cfg, &stats, &anomalies, out_pdf);
    CHECK(rc == PCAPSTAT_OK);

    /* Verify non-zero valid PDF output */
    verify_pdf_file(out_pdf);

    /* Clean up */
    anomaly_list_free(&anomalies);
    stats_free(&stats);
}

static void test_anomaly_pagination(void)
{
    cli_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);

    anomaly_list_t anomalies;
    CHECK(anomaly_list_init(&anomalies) == PCAPSTAT_OK);

    /* Append 25 anomalies to force multi-page anomaly pagination */
    for (int i = 0; i < 25; i++) {
        anomaly_t a;
        memset(&a, 0, sizeof(a));
        a.severity = (i % 3 == 0) ? ANOMALY_CRITICAL : ((i % 3 == 1) ? ANOMALY_WARNING : ANOMALY_INFO);
        snprintf(a.category, sizeof(a.category), "Synthetic Rule %d", i + 1);
        snprintf(a.subject, sizeof(a.subject), "192.168.1.%d:50000 -> 10.0.0.1:443", i + 1);
        snprintf(a.description, sizeof(a.description),
                 "High rate of suspicious indicators detected in test scenario #%d. "
                 "Threshold exceeded: observed rate 45.2%% above configured baseline limit of 5.0%%.",
                 i + 1);
        CHECK(anomaly_list_append(&anomalies, &a) == PCAPSTAT_OK);
    }

    const char *out_pdf = "/tmp/test_report_multi_anomalies.pdf";
    unlink(out_pdf);

    int rc = report_generate(&cfg, &stats, &anomalies, out_pdf);
    CHECK(rc == PCAPSTAT_OK);

    verify_pdf_file(out_pdf);
    unlink(out_pdf);

    anomaly_list_free(&anomalies);
    stats_free(&stats);
}

#if defined(__SANITIZE_ADDRESS__) || defined(__has_feature)
const char *__lsan_default_suppressions(void)
{
    return "leak:libfontconfig\n"
           "leak:libcairo\n";
}
#endif

int main(void)
{
    printf("=== test_report ===\n");
    RUN(test_null_and_invalid_args);
    RUN(test_empty_stats_report);
    RUN(test_demo_pcap_report);
    RUN(test_anomaly_pagination);
    printf("All report generator tests PASSED.\n");

    cairo_debug_reset_static_data();
    return 0;
}
