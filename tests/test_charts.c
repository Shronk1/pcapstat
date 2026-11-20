/**
 * @file test_charts.c
 * @brief Unit tests for libcairo chart rendering and PNG exports (TASK-09).
 */

#include "charts.h"
#include "common.h"
#include "parser.h"
#include "stats.h"

#include <cairo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static const unsigned char PNG_MAGIC[8] = {
    0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A
};

/**
 * @brief Verify that a file exists, is non-empty, and starts with the PNG magic header.
 */
static void verify_png_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    CHECK(f != NULL);

    int seek_rc = fseek(f, 0, SEEK_END);
    CHECK(seek_rc == 0);

    long sz = ftell(f);
    CHECK(sz > 8);

    seek_rc = fseek(f, 0, SEEK_SET);
    CHECK(seek_rc == 0);

    unsigned char header[8];
    size_t n = fread(header, 1, 8, f);
    CHECK(n == 8);
    fclose(f);

    CHECK(memcmp(header, PNG_MAGIC, 8) == 0);
}

/**
 * @brief Test argument validation on all draw and export functions.
 */
static void test_null_and_invalid_args(void)
{
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);

    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 100, 100);
    CHECK(cairo_surface_status(surf) == CAIRO_STATUS_SUCCESS);
    cairo_t *cr = cairo_create(surf);
    CHECK(cairo_status(cr) == CAIRO_STATUS_SUCCESS);

    /* NULL cr or stats */
    CHECK(chart_draw_traffic_timeline(NULL, &stats, 0, 0, 100, 100) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_traffic_timeline(cr, NULL, 0, 0, 100, 100) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_protocol_ports(NULL, &stats, 0, 0, 100, 100) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_protocol_ports(cr, NULL, 0, 0, 100, 100) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_packet_sizes(NULL, &stats, 0, 0, 100, 100) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_packet_sizes(cr, NULL, 0, 0, 100, 100) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_tcp_flags(NULL, &stats, 0, 0, 100, 100) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_tcp_flags(cr, NULL, 0, 0, 100, 100) == PCAPSTAT_ERR_ARGS);

    /* Non-positive dimensions */
    CHECK(chart_draw_traffic_timeline(cr, &stats, 0, 0, -10, 100) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_traffic_timeline(cr, &stats, 0, 0, 100, 0) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_protocol_ports(cr, &stats, 0, 0, 0, 100) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_packet_sizes(cr, &stats, 0, 0, 100, -5) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_draw_tcp_flags(cr, &stats, 0, 0, -1, -1) == PCAPSTAT_ERR_ARGS);

    /* NULL export args */
    CHECK(chart_export_traffic_timeline_png(NULL, "/tmp/out.png", 0, 0) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_export_traffic_timeline_png(&stats, NULL, 0, 0) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_export_protocol_ports_png(NULL, "/tmp/out.png", 0, 0) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_export_protocol_ports_png(&stats, NULL, 0, 0) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_export_packet_sizes_png(NULL, "/tmp/out.png", 0, 0) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_export_packet_sizes_png(&stats, NULL, 0, 0) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_export_tcp_flags_png(NULL, "/tmp/out.png", 0, 0) == PCAPSTAT_ERR_ARGS);
    CHECK(chart_export_tcp_flags_png(&stats, NULL, 0, 0) == PCAPSTAT_ERR_ARGS);
    CHECK(charts_generate_all(NULL, "/tmp") == PCAPSTAT_ERR_ARGS);
    CHECK(charts_generate_all(&stats, NULL) == PCAPSTAT_ERR_ARGS);

    cairo_destroy(cr);
    cairo_surface_destroy(surf);
    stats_free(&stats);
}

/**
 * @brief Test state preservation guarantee (cairo_save / cairo_restore).
 */
static void test_cairo_state_preservation(void)
{
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);

    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 400, 300);
    cairo_t *cr = cairo_create(surf);

    /* Set arbitrary pen state */
    cairo_set_line_width(cr, 4.25);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    cairo_set_source_rgb(cr, 0.123, 0.456, 0.789);

    /* Execute all 4 draw functions */
    CHECK(chart_draw_traffic_timeline(cr, &stats, 10, 10, 180, 130) == PCAPSTAT_OK);
    CHECK(chart_draw_protocol_ports(cr, &stats, 200, 10, 180, 130) == PCAPSTAT_OK);
    CHECK(chart_draw_packet_sizes(cr, &stats, 10, 150, 180, 130) == PCAPSTAT_OK);
    CHECK(chart_draw_tcp_flags(cr, &stats, 200, 150, 180, 130) == PCAPSTAT_OK);

    /* Check that original settings are restored */
    CHECK(cairo_get_line_width(cr) == 4.25);
    CHECK(cairo_get_line_cap(cr) == CAIRO_LINE_CAP_ROUND);

    cairo_destroy(cr);
    cairo_surface_destroy(surf);
    stats_free(&stats);
}

/**
 * @brief Test rendering and exporting with empty stats (no packets).
 */
static void test_empty_stats_placeholders(void)
{
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);

    char tmpl[] = "/tmp/pcapstat_charts_empty_XXXXXX";
    char *temp_dir = mkdtemp(tmpl);
    CHECK(temp_dir != NULL);

    int rc = charts_generate_all(&stats, temp_dir);
    CHECK(rc == PCAPSTAT_OK);

    char path[PCAPSTAT_MAX_PATH];
    static const char *files[] = {
        CHART_FILE_TRAFFIC_TIMELINE,
        CHART_FILE_PROTOCOL_PORTS,
        CHART_FILE_PACKET_SIZES,
        CHART_FILE_TCP_FLAGS
    };

    for (int i = 0; i < 4; i++) {
        snprintf(path, sizeof(path), "%s/%s", temp_dir, files[i]);
        verify_png_file(path);
        unlink(path);
    }

    rmdir(temp_dir);
    stats_free(&stats);
}

/**
 * @brief Test end-to-end chart generation from samples/demo.pcap.
 */
static void test_demo_pcap_charts(void)
{
    const char *pcap_path = "samples/demo.pcap";
    if (access(pcap_path, R_OK) != 0) {
        printf("    (skipping demo.pcap: %s not accessible)\n", pcap_path);
        return;
    }

    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);

    int parse_rc = parser_process_file(pcap_path, stats_packet_cb, &stats);
    CHECK(parse_rc == PCAPSTAT_OK);
    CHECK(stats.total_packets > 0);

    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);

    char tmpl[] = "/tmp/pcapstat_charts_demo_XXXXXX";
    char *temp_dir = mkdtemp(tmpl);
    CHECK(temp_dir != NULL);

    int gen_rc = charts_generate_all(&stats, temp_dir);
    CHECK(gen_rc == PCAPSTAT_OK);

    char path[PCAPSTAT_MAX_PATH];
    static const char *files[] = {
        CHART_FILE_TRAFFIC_TIMELINE,
        CHART_FILE_PROTOCOL_PORTS,
        CHART_FILE_PACKET_SIZES,
        CHART_FILE_TCP_FLAGS
    };

    for (int i = 0; i < 4; i++) {
        snprintf(path, sizeof(path), "%s/%s", temp_dir, files[i]);
        verify_png_file(path);

        /* Confirm that generated PNG has non-trivial size (> 5 KB) */
        struct stat st;
        CHECK(stat(path, &st) == 0);
        CHECK(st.st_size > 5000);

        unlink(path);
    }

    rmdir(temp_dir);
    stats_free(&stats);
}

/**
 * @brief Test custom dimension exports.
 */
static void test_custom_dimensions(void)
{
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);

    char path[PCAPSTAT_MAX_PATH];
    snprintf(path, sizeof(path), "/tmp/test_chart_custom_%d.png", (int)getpid());

    /* Export at 1024x768 */
    int rc = chart_export_traffic_timeline_png(&stats, path, 1024, 768);
    CHECK(rc == PCAPSTAT_OK);
    verify_png_file(path);
    unlink(path);

    /* Export at 640x400 */
    rc = chart_export_protocol_ports_png(&stats, path, 640, 400);
    CHECK(rc == PCAPSTAT_OK);
    verify_png_file(path);
    unlink(path);

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
    printf("=== test_charts ===\n");
    RUN(test_null_and_invalid_args);
    RUN(test_cairo_state_preservation);
    RUN(test_empty_stats_placeholders);
    RUN(test_demo_pcap_charts);
    RUN(test_custom_dimensions);
    printf("All chart tests PASSED.\n");

    cairo_debug_reset_static_data();
    return 0;
}
