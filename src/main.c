/**
 * @file main.c
 * @brief pcapstat entry point: CLI -> parse -> stats -> anomalies -> charts -> PDF.
 */

#include "anomaly.h"
#include "charts.h"
#include "cli.h"
#include "common.h"
#include "parser.h"
#include "report.h"
#include "stats.h"

#include <cairo.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *const k_png_names[] = {
    "traffic_timeline.png",
    "protocol_ports.png",
    "packet_sizes.png",
    "tcp_flags.png",
};

static double now_sec(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0.0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/** Length of @p dir without trailing '/' (keeps a lone "/"). */
static size_t dir_len_trimmed(const char *dir)
{
    size_t len = strlen(dir);
    while (len > 1 && dir[len - 1] == '/')
        len--;
    return len;
}

/** Build "<dir>/<name>" into @p buf. Returns PCAPSTAT_OK or PCAPSTAT_ERR_ARGS. */
static int join_path(char *buf, size_t buf_len, const char *dir, const char *name)
{
    size_t dlen = dir_len_trimmed(dir);
    const char *sep = (dlen == 1 && dir[0] == '/') ? "" : "/";
    int n = snprintf(buf, buf_len, "%.*s%s%s", (int)dlen, dir, sep, name);
    if (n < 0 || (size_t)n >= buf_len)
        return PCAPSTAT_ERR_ARGS;
    return PCAPSTAT_OK;
}

static void print_summary(const cli_config_t *cfg, const stats_ctx_t *stats,
                          const anomaly_list_t *anomalies, const char *pdf_path,
                          double elapsed)
{
    size_t crit = 0, warn = 0, info = 0;
    for (size_t i = 0; i < anomalies->count; i++) {
        switch (anomalies->items[i].severity) {
        case ANOMALY_CRITICAL: crit++; break;
        case ANOMALY_WARNING:  warn++; break;
        default:               info++; break;
        }
    }

    printf("pcapstat %s: analysis complete in %.3f s\n", PCAPSTAT_VERSION, elapsed);
    printf("  Files processed : %llu\n", (unsigned long long)stats->files_processed);
    printf("  Packets         : %llu (%llu bytes)\n",
           (unsigned long long)stats->total_packets,
           (unsigned long long)stats->total_bytes);
    printf("  Anomalies       : %zu (critical %zu, warning %zu, info %zu)\n",
           anomalies->count, crit, warn, info);
    printf("  Outputs:\n");

    char path[PCAPSTAT_MAX_PATH];
    for (size_t i = 0; i < PCAPSTAT_ARRAY_LEN(k_png_names); i++) {
        if (join_path(path, sizeof(path), cfg->output_dir, k_png_names[i]) == PCAPSTAT_OK)
            printf("    %s\n", path);
    }
    printf("    %s\n", pdf_path);
}

int main(int argc, char **argv)
{
    int rc = PCAPSTAT_OK;
    const char *prog = (argc > 0 && argv[0] != NULL) ? argv[0] : "pcapstat";
    cli_config_t cfg;
    stats_ctx_t stats;
    anomaly_list_t anomalies;
    bool stats_ready = false;
    char pdf_path[PCAPSTAT_MAX_PATH];
    double t_start = now_sec();

    memset(&cfg, 0, sizeof(cfg));
    memset(&stats, 0, sizeof(stats));
    anomaly_list_init(&anomalies);

    rc = cli_parse(argc, argv, &cfg);
    if (rc != PCAPSTAT_OK) {
        fprintf(stderr, "Try '%s --help' for more information.\n", prog);
        goto cleanup;
    }
    if (cfg.show_help) {
        cli_print_usage(stdout, prog);
        goto cleanup;
    }
    if (cfg.show_version) {
        printf("pcapstat %s\n", PCAPSTAT_VERSION);
        goto cleanup;
    }

    rc = cli_validate_and_prepare(&cfg);
    if (rc != PCAPSTAT_OK) {
        if (cfg.input_count == 0)
            cli_print_usage(stderr, prog);
        goto cleanup;
    }

    rc = join_path(pdf_path, sizeof(pdf_path), cfg.output_dir, "report.pdf");
    if (rc != PCAPSTAT_OK) {
        fprintf(stderr, "pcapstat: output path too long\n");
        goto cleanup;
    }

    rc = stats_init(&stats);
    if (rc != PCAPSTAT_OK) {
        fprintf(stderr, "pcapstat: failed to initialize statistics engine\n");
        goto cleanup;
    }
    stats_ready = true;

    for (size_t i = 0; i < cfg.input_count; i++) {
        if (cfg.verbose)
            fprintf(stderr, "pcapstat: processing '%s'\n", cfg.input_files[i]);
        rc = parser_process_file(cfg.input_files[i], stats_packet_cb, &stats);
        if (rc != PCAPSTAT_OK) {
            /* Positive values would mean the callback stopped early; the stats
             * callback only returns 0 or negative codes, so treat any non-zero
             * as failure. */
            if (rc > 0)
                rc = PCAPSTAT_ERR_PCAP;
            fprintf(stderr, "pcapstat: failed to process '%s' (error %d)\n",
                    cfg.input_files[i], rc);
            goto cleanup;
        }
        stats.files_processed++;
    }

    rc = stats_finalize(&stats);
    if (rc != PCAPSTAT_OK) {
        fprintf(stderr, "pcapstat: failed to finalize statistics (error %d)\n", rc);
        goto cleanup;
    }

    rc = anomaly_detect(&stats, &cfg.thresholds, &anomalies);
    if (rc != PCAPSTAT_OK) {
        fprintf(stderr, "pcapstat: anomaly detection failed (error %d)\n", rc);
        goto cleanup;
    }

    rc = charts_generate_all(&stats, cfg.output_dir);
    if (rc != PCAPSTAT_OK) {
        fprintf(stderr, "pcapstat: chart generation failed (error %d)\n", rc);
        goto cleanup;
    }

    rc = report_generate(&cfg, &stats, &anomalies, pdf_path);
    if (rc != PCAPSTAT_OK) {
        fprintf(stderr, "pcapstat: PDF report generation failed (error %d)\n", rc);
        goto cleanup;
    }

    print_summary(&cfg, &stats, &anomalies, pdf_path, now_sec() - t_start);

cleanup:
    anomaly_list_free(&anomalies);
    if (stats_ready)
        stats_free(&stats);
    cli_free(&cfg);
    /* Release cairo's process-wide font/scaled-font caches so leak checkers
     * only report real leaks. Safe here: every surface/context is destroyed. */
    cairo_debug_reset_static_data();
    return rc == PCAPSTAT_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
