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
#include <math.h>
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

/* FIX-06: human-readable duration instead of raw seconds. */
static void test_format_duration(void)
{
    char buf[48];
    report_format_duration(0.0, buf, sizeof(buf));
    CHECK(strcmp(buf, "0.00 s") == 0);
    report_format_duration(12.345, buf, sizeof(buf));
    CHECK(strcmp(buf, "12.35 s") == 0 || strcmp(buf, "12.34 s") == 0);
    report_format_duration(59.99, buf, sizeof(buf));
    CHECK(strcmp(buf, "59.99 s") == 0);
    report_format_duration(60.0, buf, sizeof(buf));
    CHECK(strcmp(buf, "00:01:00") == 0);
    report_format_duration(3725.9, buf, sizeof(buf));
    CHECK(strcmp(buf, "01:02:05") == 0);
    report_format_duration(86399.0, buf, sizeof(buf));
    CHECK(strcmp(buf, "23:59:59") == 0);
    report_format_duration(86400.0, buf, sizeof(buf));
    CHECK(strcmp(buf, "1d 00:00:00") == 0);
    /* 3 days, 4 h, 5 min, 6 s */
    report_format_duration(3.0 * 86400.0 + 4 * 3600 + 5 * 60 + 6, buf,
                           sizeof(buf));
    CHECK(strcmp(buf, "3d 04:05:06") == 0);
    /* INT32_MIN..INT32_MAX span (extreme timestamps) */
    report_format_duration(4294967295.0, buf, sizeof(buf));
    CHECK(strcmp(buf, "49710d 06:28:15") == 0);
    /* Garbage in: clamped, never UB (strict UBSan in unit tests). */
    report_format_duration(-5.0, buf, sizeof(buf));
    CHECK(strcmp(buf, "0.00 s") == 0);
    report_format_duration(NAN, buf, sizeof(buf));
    CHECK(strcmp(buf, "0.00 s") == 0);
    report_format_duration(1e300, buf, sizeof(buf));
    CHECK(buf[0] != '\0' && strchr(buf, 'd') != NULL);
    /* Small buffers stay NUL-terminated; NULL/0 are no-ops. */
    char small[4];
    report_format_duration(3725.0, small, sizeof(small));
    CHECK(strcmp(small, "01:") == 0);
    report_format_duration(1.0, NULL, 10);
    report_format_duration(1.0, small, 0);
}

/* H4 display: avg_bps is bits/s; lowercase kbps, decimal SI units. */
static void test_format_bitrate(void)
{
    char buf[32];
    report_format_bitrate(0.0, buf, sizeof(buf));
    CHECK(strcmp(buf, "0 bps") == 0);
    report_format_bitrate(999.0, buf, sizeof(buf));
    CHECK(strcmp(buf, "999 bps") == 0);
    report_format_bitrate(1000.0, buf, sizeof(buf));
    CHECK(strcmp(buf, "1.0 kbps") == 0);
    report_format_bitrate(8.0 * 1500.0, buf, sizeof(buf)); /* 1500 B/s */
    CHECK(strcmp(buf, "12.0 kbps") == 0);
    report_format_bitrate(2.5e6, buf, sizeof(buf));
    CHECK(strcmp(buf, "2.50 Mbps") == 0);
    report_format_bitrate(1.25e9, buf, sizeof(buf));
    CHECK(strcmp(buf, "1.25 Gbps") == 0);
    report_format_bitrate(-1.0, buf, sizeof(buf));
    CHECK(strcmp(buf, "0 bps") == 0);
    report_format_bitrate(INFINITY, buf, sizeof(buf));
    CHECK(strcmp(buf, "0 bps") == 0);
}

/* A report with every FIX-06 category populated (non-IP, fragments,
 * truncated file, out-of-order) and no input files listed renders. */
static void test_report_new_counters(void)
{
    cli_config_t cfg;
    memset(&cfg, 0, sizeof(cfg)); /* no inputs: sources show "(none)" */

    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    parsed_packet_t p;
    memset(&p, 0, sizeof(p));
    p.timestamp = 1.0;
    p.wire_len = 60;
    p.is_non_ip = true;
    CHECK(stats_update(&stats, &p) == PCAPSTAT_OK);
    memset(&p, 0, sizeof(p));
    p.timestamp = 3.0 * 86400.0;
    p.wire_len = 1514;
    p.ip_version = 4;
    p.src_ip[0] = 10;
    p.dst_ip[0] = 10;
    p.dst_ip[3] = 2;
    p.proto = 17;
    p.is_fragment = true;
    CHECK(stats_update(&stats, &p) == PCAPSTAT_OK);
    stats.files_processed = 1;
    stats.truncated_files = 1;
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);
    CHECK(stats.non_ip_packets == 1 && stats.ip_fragments == 1);

    anomaly_list_t anomalies;
    CHECK(anomaly_list_init(&anomalies) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&stats, NULL, &anomalies) == PCAPSTAT_OK);
    CHECK(anomalies.count == 1);
    CHECK(strcmp(anomalies.items[0].category, "Capture Integrity") == 0);

    const char *out_pdf = "/tmp/test_report_fix06.pdf";
    unlink(out_pdf);
    CHECK(report_generate(&cfg, &stats, &anomalies, out_pdf) == PCAPSTAT_OK);
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
    RUN(test_format_duration);
    RUN(test_format_bitrate);
    RUN(test_report_new_counters);
    printf("All report generator tests PASSED.\n");

    cairo_debug_reset_static_data();
    return 0;
}
