/**
 * @file test_charts.c
 * @brief Unit tests for libcairo chart rendering and PNG exports (TASK-09).
 */

#include "charts.h"
#include "common.h"
#include "parser.h"
#include "stats.h"

#include <cairo.h>
#if CAIRO_HAS_SCRIPT_SURFACE
#include <cairo-script.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
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

static const char *const CHART_FILES[4] = {
    CHART_FILE_TRAFFIC_TIMELINE,
    CHART_FILE_PROTOCOL_PORTS,
    CHART_FILE_PACKET_SIZES,
    CHART_FILE_TCP_FLAGS
};

/**
 * @brief Verify (then delete) the 4 chart PNGs in @p dir.
 */
static void verify_and_remove_charts(const char *dir)
{
    char path[PCAPSTAT_MAX_PATH];
    for (int i = 0; i < 4; i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, CHART_FILES[i]);
        verify_png_file(path);
        CHECK(unlink(path) == 0);
    }
}

/**
 * @brief Feed one well-formed IPv4 packet 10.0.0.1:40000 -> 10.0.0.2:@p dst_port.
 */
static void add_packet(stats_ctx_t *stats, double ts, uint8_t proto,
                       uint16_t dst_port, uint8_t tcp_flags)
{
    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.timestamp = ts;
    pkt.wire_len = 100;
    pkt.cap_len = 100;
    pkt.ip_version = 4;
    pkt.src_ip[0] = 10;
    pkt.src_ip[3] = 1;
    pkt.dst_ip[0] = 10;
    pkt.dst_ip[3] = 2;
    pkt.proto = proto;
    pkt.src_port = 40000;
    pkt.dst_port = dst_port;
    pkt.tcp_flags = tcp_flags;
    CHECK(stats_update(stats, &pkt) == PCAPSTAT_OK);
}

typedef int (*chart_draw_fn_t)(cairo_t *cr, const stats_ctx_t *stats,
                               double x, double y, double width, double height);

static const chart_draw_fn_t DRAW_FNS[4] = {
    chart_draw_traffic_timeline,
    chart_draw_protocol_ports,
    chart_draw_packet_sizes,
    chart_draw_tcp_flags
};

/**
 * @brief Draw all 4 charts into an in-memory 800x500 image; all must succeed.
 */
static void draw_all_to_image(const stats_ctx_t *stats)
{
    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 800, 500);
    cairo_t *cr = cairo_create(surf);
    for (int i = 0; i < 4; i++) {
        CHECK(DRAW_FNS[i](cr, stats, 0, 0, 800, 500) == PCAPSTAT_OK);
    }
    CHECK(cairo_status(cr) == CAIRO_STATUS_SUCCESS);
    cairo_destroy(cr);
    cairo_surface_destroy(surf);
}

/* -------------------------------------------------------------------
 * Text capture: every string a chart passes to cairo_show_text(), in
 * drawing order. The cairo script surface records each call as
 * "(<text>) [...] ... show-text-glyphs" with '(', ')' and '\' escaped.
 * ------------------------------------------------------------------- */

#define MAX_CHART_TEXTS 64

typedef struct {
    size_t count;
    char items[MAX_CHART_TEXTS][128];
} chart_texts_t;

#if CAIRO_HAS_SCRIPT_SURFACE
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} membuf_t;

static cairo_status_t membuf_write(void *closure, const unsigned char *data,
                                   unsigned int length)
{
    membuf_t *m = (membuf_t *)closure;
    if (m->len + length + 1 > m->cap) {
        size_t ncap = m->cap ? m->cap : 65536;
        while (ncap < m->len + length + 1) {
            ncap *= 2;
        }
        char *nd = (char *)realloc(m->data, ncap);
        if (!nd) {
            return CAIRO_STATUS_WRITE_ERROR;
        }
        m->data = nd;
        m->cap = ncap;
    }
    memcpy(m->data + m->len, data, length);
    m->len += length;
    m->data[m->len] = '\0';
    return CAIRO_STATUS_SUCCESS;
}

/** Parse the PostScript string literal at @p s (s[0] == '('). */
static bool parse_ps_string(const char *s, const char *end, char *out, size_t out_sz)
{
    size_t o = 0;
    int depth = 0;
    for (const char *p = s; p < end; p++) {
        char c = *p;
        if (c == '\\' && p + 1 < end) {
            c = *++p;
            if (c >= '0' && c <= '7') {
                int v = 0;
                int k = 0;
                while (k < 3 && p < end && *p >= '0' && *p <= '7') {
                    v = v * 8 + (*p - '0');
                    p++;
                    k++;
                }
                p--;
                c = (char)v;
            } else if (c == 'n') {
                c = '\n';
            } else if (c == 't') {
                c = '\t';
            }
        } else if (c == '(') {
            if (depth++ == 0) {
                continue;
            }
        } else if (c == ')') {
            if (--depth == 0) {
                out[o] = '\0';
                return true;
            }
        }
        if (o + 1 >= out_sz) {
            return false;
        }
        out[o++] = c;
    }
    return false;
}
#endif

/**
 * @brief Render one chart (width x height) and collect its text strings.
 * @return false if the cairo build has no script surface (test skipped).
 */
static bool capture_chart_texts(chart_draw_fn_t fn, const stats_ctx_t *stats,
                                double width, double height, chart_texts_t *out)
{
    memset(out, 0, sizeof(*out));
#if CAIRO_HAS_SCRIPT_SURFACE
    membuf_t m = {NULL, 0, 0};
    cairo_device_t *dev = cairo_script_create_for_stream(membuf_write, &m);
    CHECK(cairo_device_status(dev) == CAIRO_STATUS_SUCCESS);
    cairo_surface_t *surf = cairo_script_surface_create(dev, CAIRO_CONTENT_COLOR_ALPHA,
                                                        width, height);
    cairo_t *cr = cairo_create(surf);
    CHECK(fn(cr, stats, 0, 0, width, height) == PCAPSTAT_OK);
    cairo_destroy(cr);
    cairo_surface_finish(surf);
    cairo_surface_destroy(surf);
    cairo_device_finish(dev);
    cairo_device_destroy(dev);
    CHECK(m.data != NULL);

    static const char op[] = "show-text-glyphs";
    const size_t op_len = sizeof(op) - 1;
    const char *end = m.data + m.len;
    for (const char *p = m.data; p + op_len <= end; p++) {
        if (memcmp(p, op, op_len) != 0) {
            continue;
        }
        const char *line = p;
        while (line > m.data && line[-1] != '\n') {
            line--;
        }
        const char *open = (const char *)memchr(line, '(', (size_t)(p - line));
        CHECK(open != NULL);
        CHECK(out->count < MAX_CHART_TEXTS);
        CHECK(parse_ps_string(open, p, out->items[out->count],
                              sizeof(out->items[out->count])));
        out->count++;
        p += op_len - 1;
    }
    free(m.data);
    return true;
#else
    (void)fn;
    (void)stats;
    (void)width;
    (void)height;
    printf("    (skipping text checks: cairo built without script surface)\n");
    return false;
#endif
}

static bool texts_contain(const chart_texts_t *t, const char *s)
{
    for (size_t i = 0; i < t->count; i++) {
        if (strcmp(t->items[i], s) == 0) {
            return true;
        }
    }
    return false;
}

/** Check t->items[first .. first+n) against @p expected, printing a diff. */
static void check_texts(const chart_texts_t *t, size_t first,
                        const char *const *expected, size_t n)
{
    CHECK(first + n <= t->count);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(t->items[first + i], expected[i]) != 0) {
            fprintf(stderr, "    text[%zu] = \"%s\", expected \"%s\"\n",
                    first + i, t->items[first + i], expected[i]);
        }
        CHECK(strcmp(t->items[first + i], expected[i]) == 0);
    }
}

/* Timeline text order: title, 5 Y ticks, 5 X ticks, "TCP", "UDP". */
#define TL_TEXT_COUNT  13
#define TL_FIRST_YTICK 1
#define TL_FIRST_XTICK 6

/* -------------------------------------------------------------------
 * Pixel helpers (timeline geometry at 800x500)
 * ------------------------------------------------------------------- */

#define TL_IMG_W 800
#define TL_IMG_H 500
/* The plot spans y ~57..459 at 800x500; rate 0 is drawn at y ~459. */
#define TL_ZERO_BAND_Y 425
/* Column inside the plot, away from vertical gridlines and the legend. */
#define TL_PROBE_X 320

static cairo_surface_t *render_timeline(const stats_ctx_t *stats)
{
    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32,
                                                       TL_IMG_W, TL_IMG_H);
    cairo_t *cr = cairo_create(surf);
    CHECK(chart_draw_traffic_timeline(cr, stats, 0, 0, TL_IMG_W, TL_IMG_H) == PCAPSTAT_OK);
    cairo_destroy(cr);
    cairo_surface_flush(surf);
    return surf;
}

/** Count TCP-blue or UDP-orange pixels in column @p x, rows [y0, y1). */
static int count_series_pixels(cairo_surface_t *surf, int x, int y0, int y1)
{
    const unsigned char *data = cairo_image_surface_get_data(surf);
    int stride = cairo_image_surface_get_stride(surf);
    int n = 0;
    for (int y = y0; y < y1; y++) {
        uint32_t px;
        memcpy(&px, data + (size_t)y * (size_t)stride + (size_t)x * 4, sizeof(px));
        int r = (int)((px >> 16) & 0xff);
        int g = (int)((px >> 8) & 0xff);
        int b = (int)(px & 0xff);
        bool blue = b > 150 && b - r > 60 && b - g > 40;
        bool orange = r > 180 && r - b > 60 && r - g > 30;
        if (blue || orange) {
            n++;
        }
    }
    return n;
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

/* Base epoch for synthetic captures (2023-11-14 22:13:20 UTC). */
#define T0 1700000000.0

/**
 * @brief State preservation also holds on the data paths (not just placeholders).
 */
static void test_cairo_state_preservation_with_data(void)
{
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    add_packet(&stats, T0, IPPROTO_TCP, 443, TH_SYN);
    add_packet(&stats, T0 + 5.0, IPPROTO_UDP, 53, 0);
    add_packet(&stats, T0 + 86400.0, IPPROTO_TCP, 443, TH_ACK);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);

    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 800, 600);
    cairo_t *cr = cairo_create(surf);
    cairo_set_line_width(cr, 4.25);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    cairo_set_font_size(cr, 33.0);

    CHECK(chart_draw_traffic_timeline(cr, &stats, 0, 0, 400, 300) == PCAPSTAT_OK);
    CHECK(chart_draw_protocol_ports(cr, &stats, 400, 0, 400, 300) == PCAPSTAT_OK);
    CHECK(chart_draw_packet_sizes(cr, &stats, 0, 300, 400, 300) == PCAPSTAT_OK);
    CHECK(chart_draw_tcp_flags(cr, &stats, 400, 300, 400, 300) == PCAPSTAT_OK);

    CHECK(cairo_get_line_width(cr) == 4.25);
    CHECK(cairo_get_line_cap(cr) == CAIRO_LINE_CAP_ROUND);
    cairo_matrix_t fm;
    cairo_get_font_matrix(cr, &fm);
    CHECK(fm.xx == 33.0 && fm.yy == 33.0);
    CHECK(cairo_status(cr) == CAIRO_STATUS_SUCCESS);

    cairo_destroy(cr);
    cairo_surface_destroy(surf);
    stats_free(&stats);
}

/**
 * @brief C2 regression: buckets at INT32_MIN and INT32_MAX seconds (a span
 *        > INT_MAX s) used to hit `(int)offset_sec` (UB; release builds
 *        printed "+-2147483648s"). All four charts must render and the
 *        X-axis must use non-negative day-scale labels.
 */
static void test_timeline_extreme_int32_timestamps(void)
{
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    add_packet(&stats, (double)INT32_MIN, IPPROTO_TCP, 80, TH_SYN);
    add_packet(&stats, (double)INT32_MAX, IPPROTO_TCP, 80, TH_SYN);
    add_packet(&stats, (double)INT32_MAX, IPPROTO_UDP, 53, 0);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);
    CHECK(stats.timeline_count == 2);
    CHECK(stats.timeline[0].sec == INT32_MIN);
    CHECK(stats.timeline[1].sec == INT32_MAX);

    char tmpl[] = "/tmp/pcapstat_charts_int32_XXXXXX";
    char *temp_dir = mkdtemp(tmpl);
    CHECK(temp_dir != NULL);
    CHECK(charts_generate_all(&stats, temp_dir) == PCAPSTAT_OK);
    verify_and_remove_charts(temp_dir);
    CHECK(rmdir(temp_dir) == 0);

    /* Span = 2^32 s = 49710 d 06:28:16 */
    chart_texts_t t;
    if (capture_chart_texts(chart_draw_traffic_timeline, &stats, 800, 500, &t)) {
        static const char *const xticks[5] = {
            "+0d00h", "+12427d14h", "+24855d03h", "+37282d17h", "+49710d06h"
        };
        CHECK(t.count == TL_TEXT_COUNT);
        check_texts(&t, TL_FIRST_XTICK, xticks, 5);
    }

    stats_free(&stats);
}

/**
 * @brief C2 regression (int64 range): buckets near +/-8.9e18 s, where the
 *        old `t_end - t_start` and `b->sec - t_start` overflowed int64_t,
 *        including a downsampled bucket whose span_sec exceeds INT64_MAX.
 */
static void test_timeline_extreme_int64_timestamps(void)
{
    stats_ctx_t stats;
    chart_texts_t t;

    /* Two raw buckets 1.78e19 s apart */
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    add_packet(&stats, -8.9e18, IPPROTO_TCP, 80, TH_SYN);
    add_packet(&stats, 8.9e18, IPPROTO_UDP, 53, 0);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);
    CHECK(stats.timeline_count == 2);
    draw_all_to_image(&stats);
    if (capture_chart_texts(chart_draw_traffic_timeline, &stats, 800, 500, &t)) {
        CHECK(t.count == TL_TEXT_COUNT);
        CHECK(strcmp(t.items[TL_FIRST_XTICK], "+0d00h") == 0);
        for (size_t i = TL_FIRST_XTICK; i < TL_FIRST_XTICK + 5; i++) {
            CHECK(t.items[i][0] == '+');
            CHECK(strchr(t.items[i], '-') == NULL);
        }
    }
    stats_free(&stats);

    /* 240 raw buckets -> 120 pairs; pair 0 spans -8.9e18 .. +8.9e18. */
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    add_packet(&stats, -8.9e18, IPPROTO_TCP, 80, TH_SYN);
    for (int k = 0; k < 239; k++) {
        /* 1024 s steps: the spacing of doubles near 8.9e18 */
        add_packet(&stats, 8.9e18 + 1024.0 * k, IPPROTO_UDP, 53, 0);
    }
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);
    CHECK(stats.timeline_count == 120);
    CHECK(stats.timeline[0].span_sec > (uint64_t)INT64_MAX);
    draw_all_to_image(&stats);
    if (capture_chart_texts(chart_draw_traffic_timeline, &stats, 800, 500, &t)) {
        CHECK(t.count == TL_TEXT_COUNT);
        for (size_t i = TL_FIRST_XTICK; i < TL_FIRST_XTICK + 5; i++) {
            CHECK(t.items[i][0] == '+');
            CHECK(strchr(t.items[i], '-') == NULL);
        }
    }
    stats_free(&stats);
}

/**
 * @brief C2: the X-axis unit follows the capture span:
 *        "+12s", "+05:30", "+3h05m", "+2d04h" (and decimals below 60 s).
 */
static void test_timeline_axis_label_formats(void)
{
    static const struct {
        double span;
        const char *xticks[5];
    } cases[] = {
        {2.0,      {"+0s", "+0.5s", "+1s", "+1.5s", "+2s"}},
        {12.0,     {"+0s", "+3s", "+6s", "+9s", "+12s"}},
        {330.0,    {"+00:00", "+01:23", "+02:45", "+04:08", "+05:30"}},
        {11100.0,  {"+0h00m", "+0h46m", "+1h33m", "+2h19m", "+3h05m"}},
        {187200.0, {"+0d00h", "+0d13h", "+1d02h", "+1d15h", "+2d04h"}},
    };

    for (size_t c = 0; c < PCAPSTAT_ARRAY_LEN(cases); c++) {
        stats_ctx_t stats;
        CHECK(stats_init(&stats) == PCAPSTAT_OK);
        /* First bucket starts at T0, last one ends at T0 + span. */
        add_packet(&stats, T0, IPPROTO_TCP, 80, TH_ACK);
        add_packet(&stats, T0 + cases[c].span - 1.0, IPPROTO_TCP, 80, TH_ACK);
        CHECK(stats_finalize(&stats) == PCAPSTAT_OK);

        chart_texts_t t;
        if (capture_chart_texts(chart_draw_traffic_timeline, &stats, 800, 500, &t)) {
            CHECK(t.count == TL_TEXT_COUNT);
            check_texts(&t, TL_FIRST_XTICK, cases[c].xticks, 5);
        }
        stats_free(&stats);
    }
}

/**
 * @brief M3 regression: fractional ticks of small axes are printed exactly
 *        (they used to collapse to "0 0 0 1 1"); integer ticks stay integers.
 */
static void test_axis_ticks_are_distinct(void)
{
    stats_ctx_t stats;
    chart_texts_t t;

    /* 1 TCP packet/s for 10 s: rate axis 0..1 */
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    for (int s = 0; s < 10; s++) {
        add_packet(&stats, T0 + s, IPPROTO_TCP, 80, TH_ACK);
    }
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);
    if (capture_chart_texts(chart_draw_traffic_timeline, &stats, 800, 500, &t)) {
        static const char *const yticks[5] = {"0", "0.25", "0.5", "0.75", "1"};
        static const char *const xticks[5] = {"+0s", "+2.5s", "+5s", "+7.5s", "+10s"};
        CHECK(t.count == TL_TEXT_COUNT);
        check_texts(&t, TL_FIRST_YTICK, yticks, 5);
        check_texts(&t, TL_FIRST_XTICK, xticks, 5);
    }
    /* 10 ACKs: count axis 0..10 has quarter ticks 2.5 and 7.5 */
    if (capture_chart_texts(chart_draw_tcp_flags, &stats, 800, 500, &t)) {
        static const char *const yticks[5] = {"0", "2.5", "5", "7.5", "10"};
        check_texts(&t, 1, yticks, 5);
    }
    stats_free(&stats);

    /* Port with 2 packets: X axis 0..2 */
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    add_packet(&stats, T0, IPPROTO_TCP, 443, TH_SYN);
    add_packet(&stats, T0 + 1.0, IPPROTO_TCP, 443, TH_ACK);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);
    if (capture_chart_texts(chart_draw_protocol_ports, &stats, 800, 500, &t)) {
        static const char *const xticks[5] = {"0", "0.5", "1", "1.5", "2"};
        check_texts(&t, 1, xticks, 5);
    }
    stats_free(&stats);

    /* 20 packets: integer ticks keep the integer format */
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    for (int i = 0; i < 20; i++) {
        add_packet(&stats, T0 + i, IPPROTO_TCP, 443, TH_ACK);
    }
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);
    if (capture_chart_texts(chart_draw_packet_sizes, &stats, 800, 500, &t)) {
        static const char *const yticks[5] = {"0", "5", "10", "15", "20"};
        check_texts(&t, 1, yticks, 5);
    }
    stats_free(&stats);
}

/**
 * @brief M2 regression: no line is interpolated across a gap without traffic.
 *
 * Two buckets 3 days apart (TCP 2 -> 4 pkt/s, UDP 3 -> 1 pkt/s) used to be
 * joined by straight lines through the middle of the plot; now both series
 * drop to 0 after the first bucket and stay there until the next one.
 */
static void test_timeline_gap_drops_to_zero(void)
{
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    for (int i = 0; i < 2; i++) {
        add_packet(&stats, T0, IPPROTO_TCP, 80, TH_ACK);
    }
    for (int i = 0; i < 3; i++) {
        add_packet(&stats, T0, IPPROTO_UDP, 53, 0);
    }
    for (int i = 0; i < 4; i++) {
        add_packet(&stats, T0 + 3 * 86400.0, IPPROTO_TCP, 80, TH_ACK);
    }
    add_packet(&stats, T0 + 3 * 86400.0, IPPROTO_UDP, 53, 0);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);
    CHECK(stats.timeline_count == 2);

    cairo_surface_t *surf = render_timeline(&stats);
    CHECK(count_series_pixels(surf, TL_PROBE_X, 0, TL_ZERO_BAND_Y) == 0);
    CHECK(count_series_pixels(surf, TL_PROBE_X, TL_ZERO_BAND_Y, TL_IMG_H) > 0);
    cairo_surface_destroy(surf);
    stats_free(&stats);

    /* Contiguous buckets (no gap) are still joined above zero. */
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    for (int s = 0; s < 3; s++) {
        for (int i = 0; i < 3; i++) {
            add_packet(&stats, T0 + s, IPPROTO_TCP, 80, TH_ACK);
        }
    }
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);
    CHECK(stats.timeline_count == 3);
    surf = render_timeline(&stats);
    CHECK(count_series_pixels(surf, TL_PROBE_X, 0, TL_ZERO_BAND_Y) > 0);
    cairo_surface_destroy(surf);
    stats_free(&stats);

    /* A single bucket (one packet) is drawn, not left as an invisible point. */
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    add_packet(&stats, T0, IPPROTO_TCP, 80, TH_SYN);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);
    CHECK(stats.timeline_count == 1);
    surf = render_timeline(&stats);
    CHECK(count_series_pixels(surf, TL_PROBE_X, 0, TL_ZERO_BAND_Y) > 0);
    cairo_surface_destroy(surf);
    stats_free(&stats);
}

/**
 * @brief M9 regression: TCP/53 and UDP/53 are two bars with distinct labels
 *        (both used to read "53 (DNS)").
 */
static void test_port_labels_include_protocol(void)
{
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    for (int i = 0; i < 3; i++) {
        add_packet(&stats, T0 + i, IPPROTO_TCP, 53, TH_ACK);
    }
    for (int i = 0; i < 2; i++) {
        add_packet(&stats, T0 + i, IPPROTO_UDP, 53, 0);
    }
    add_packet(&stats, T0, IPPROTO_UDP, 65535, 0);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);

    chart_texts_t t;
    if (capture_chart_texts(chart_draw_protocol_ports, &stats, 800, 500, &t)) {
        CHECK(texts_contain(&t, "53/tcp (DNS)"));
        CHECK(texts_contain(&t, "53/udp (DNS)"));
        CHECK(texts_contain(&t, "65535/udp (Unknown)"));
        CHECK(!texts_contain(&t, "53 (DNS)"));
    }
    stats_free(&stats);
}

/**
 * @brief M9: tcp_flags has an 8th "Suspicious" bar = null + xmas + SYN+FIN + SYN+RST.
 */
static void test_tcp_flags_suspicious_bar(void)
{
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    stats.tcp_packets = 10;
    stats.syn = 2;
    stats.ack = 6;
    stats.fin = 2;
    stats.rst = 1;
    stats.psh = 1;
    stats.urg = 1;
    stats.null_scan_pkts = 1;
    stats.xmas_scan_pkts = 1;
    stats.syn_fin_pkts = 1;
    stats.syn_rst_pkts = 1;

    chart_texts_t t;
    if (capture_chart_texts(chart_draw_tcp_flags, &stats, 800, 500, &t)) {
        /* title, 5 ticks, then per bar: [percentage], label */
        static const char *const expected[] = {
            "20.0%", "SYN", "SYN-ACK", "60.0%", "ACK", "20.0%", "FIN",
            "10.0%", "RST", "10.0%", "PSH", "10.0%", "URG", "40.0%", "Suspicious"
        };
        CHECK(t.count == 6 + PCAPSTAT_ARRAY_LEN(expected));
        check_texts(&t, 6, expected, PCAPSTAT_ARRAY_LEN(expected));
    }
    draw_all_to_image(&stats);
    stats_free(&stats);
}

/**
 * @brief The charts.h promise of PCAPSTAT_ERR_RENDER: a Cairo context in an
 *        error state is reported instead of silently returning PCAPSTAT_OK.
 */
static void test_render_error_status(void)
{
    stats_ctx_t empty;
    stats_ctx_t full;
    CHECK(stats_init(&empty) == PCAPSTAT_OK);
    CHECK(stats_finalize(&empty) == PCAPSTAT_OK);
    CHECK(stats_init(&full) == PCAPSTAT_OK);
    add_packet(&full, T0, IPPROTO_TCP, 443, TH_SYN);
    add_packet(&full, T0 + 1.0, IPPROTO_UDP, 53, 0);
    CHECK(stats_finalize(&full) == PCAPSTAT_OK);

    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 400, 300);
    cairo_t *cr = cairo_create(surf);
    cairo_restore(cr); /* unbalanced restore: sticky CAIRO_STATUS_INVALID_RESTORE */
    CHECK(cairo_status(cr) == CAIRO_STATUS_INVALID_RESTORE);

    for (int i = 0; i < 4; i++) {
        CHECK(DRAW_FNS[i](cr, &empty, 0, 0, 400, 300) == PCAPSTAT_ERR_RENDER);
        CHECK(DRAW_FNS[i](cr, &full, 0, 0, 400, 300) == PCAPSTAT_ERR_RENDER);
    }

    cairo_destroy(cr);
    cairo_surface_destroy(surf);
    stats_free(&empty);
    stats_free(&full);
}

/**
 * @brief Output directory join: trailing slashes are trimmed (like main.c),
 *        so "dir/" does not produce "dir//x.png" and a directory string with
 *        many trailing slashes still fits PCAPSTAT_MAX_PATH; "" is rejected.
 */
static void test_output_dir_trailing_slashes(void)
{
    stats_ctx_t stats;
    CHECK(stats_init(&stats) == PCAPSTAT_OK);
    CHECK(stats_finalize(&stats) == PCAPSTAT_OK);

    char tmpl[] = "/tmp/pcapstat_charts_slash_XXXXXX";
    char *temp_dir = mkdtemp(tmpl);
    CHECK(temp_dir != NULL);

    char dir[PCAPSTAT_MAX_PATH];
    snprintf(dir, sizeof(dir), "%s/", temp_dir);
    CHECK(charts_generate_all(&stats, dir) == PCAPSTAT_OK);
    verify_and_remove_charts(temp_dir);

    /* "<dir>////...": "%s/%s" would not fit, the trimmed path does. */
    static char long_dir[PCAPSTAT_MAX_PATH];
    size_t n = strlen(temp_dir);
    memcpy(long_dir, temp_dir, n);
    memset(long_dir + n, '/', sizeof(long_dir) - n - 8);
    long_dir[sizeof(long_dir) - 8] = '\0';
    CHECK(strlen(long_dir) + 1 + strlen(CHART_FILE_TRAFFIC_TIMELINE) >= PCAPSTAT_MAX_PATH);
    CHECK(charts_generate_all(&stats, long_dir) == PCAPSTAT_OK);
    verify_and_remove_charts(temp_dir);

    CHECK(charts_generate_all(&stats, "") == PCAPSTAT_ERR_ARGS);

    CHECK(rmdir(temp_dir) == 0);
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
    RUN(test_cairo_state_preservation_with_data);
    RUN(test_timeline_extreme_int32_timestamps);
    RUN(test_timeline_extreme_int64_timestamps);
    RUN(test_timeline_axis_label_formats);
    RUN(test_axis_ticks_are_distinct);
    RUN(test_timeline_gap_drops_to_zero);
    RUN(test_port_labels_include_protocol);
    RUN(test_tcp_flags_suspicious_bar);
    RUN(test_render_error_status);
    RUN(test_output_dir_trailing_slashes);
    printf("All chart tests PASSED.\n");

    cairo_debug_reset_static_data();
    return 0;
}
