/**
 * @file report.c
 * @brief Implementation of multi-page PDF report generation using libcairo.
 */

#include "report.h"
#include "charts.h"
#include "common.h"
#include "parser.h"
#include "stats.h"

#include <cairo.h>
#include <cairo-pdf.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* -------------------------------------------------------------------
 * Color Palette Constants (RGB 0.0 - 1.0)
 * ------------------------------------------------------------------- */

/* Neutral & Backgrounds */
#define RPT_COLOR_WHITE_R       1.00
#define RPT_COLOR_WHITE_G       1.00
#define RPT_COLOR_WHITE_B       1.00

#define RPT_COLOR_BG_CARD_R     0.97
#define RPT_COLOR_BG_CARD_G     0.98
#define RPT_COLOR_BG_CARD_B     0.99

#define RPT_COLOR_ZEBRA_R       0.965
#define RPT_COLOR_ZEBRA_G       0.973
#define RPT_COLOR_ZEBRA_B       0.984

#define RPT_COLOR_BORDER_R      0.88
#define RPT_COLOR_BORDER_G      0.90
#define RPT_COLOR_BORDER_B      0.93

#define RPT_COLOR_TH_BG_R       0.93
#define RPT_COLOR_TH_BG_G       0.95
#define RPT_COLOR_TH_BG_B       0.97

/* Text Colors */
#define RPT_COLOR_TEXT_MAIN_R   0.12
#define RPT_COLOR_TEXT_MAIN_G   0.16
#define RPT_COLOR_TEXT_MAIN_B   0.23

#define RPT_COLOR_TEXT_MUTED_R  0.42
#define RPT_COLOR_TEXT_MUTED_G  0.48
#define RPT_COLOR_TEXT_MUTED_B  0.56

/* Brand & Accents */
#define RPT_COLOR_PRIMARY_R     0.15
#define RPT_COLOR_PRIMARY_G     0.39
#define RPT_COLOR_PRIMARY_B     0.92

/* Severity Colors */
#define RPT_COLOR_CRIT_R        0.86
#define RPT_COLOR_CRIT_G        0.15
#define RPT_COLOR_CRIT_B        0.15

#define RPT_COLOR_WARN_R        0.95
#define RPT_COLOR_WARN_G        0.55
#define RPT_COLOR_WARN_B        0.05

#define RPT_COLOR_INFO_R        0.14
#define RPT_COLOR_INFO_G        0.48
#define RPT_COLOR_INFO_B        0.93

#define RPT_COLOR_OK_R          0.09
#define RPT_COLOR_OK_G          0.63
#define RPT_COLOR_OK_B          0.30

/* -------------------------------------------------------------------
 * Formatting and Drawing Helpers
 * ------------------------------------------------------------------- */

static void format_bytes(uint64_t bytes, char *buf, size_t sz)
{
    if (bytes >= 1024ULL * 1024ULL * 1024ULL) {
        snprintf(buf, sz, "%.2f GB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024ULL * 1024ULL) {
        snprintf(buf, sz, "%.2f MB", (double)bytes / (1024.0 * 1024.0));
    } else if (bytes >= 1024ULL) {
        snprintf(buf, sz, "%.1f KB", (double)bytes / 1024.0);
    } else {
        snprintf(buf, sz, "%" PRIu64 " B", bytes);
    }
}

static void format_count_commas(uint64_t val, char *buf, size_t sz)
{
    char raw[32];
    snprintf(raw, sizeof(raw), "%" PRIu64, val);
    size_t len = strlen(raw);
    size_t commas = (len > 0) ? (len - 1) / 3 : 0;
    if (len + commas >= sz) {
        snprintf(buf, sz, "%" PRIu64, val);
        return;
    }
    size_t j = len + commas;
    buf[j--] = '\0';
    size_t c = 0;
    for (int i = (int)len - 1; i >= 0; i--) {
        buf[j--] = raw[i];
        c++;
        if (c == 3 && i > 0) {
            buf[j--] = ',';
            c = 0;
        }
    }
}

void report_format_duration(double seconds, char *buf, size_t sz)
{
    if (buf == NULL || sz == 0)
        return;
    if (!isfinite(seconds) || seconds < 0.0)
        seconds = 0.0;
    if (seconds < 60.0) {
        snprintf(buf, sz, "%.2f s", seconds);
        return;
    }
    /* Whole seconds; clamp so the uint64_t conversion is always defined
     * (1.8e19 s is far beyond any usable capture span). */
    double whole = floor(seconds);
    if (whole > 1.8e19)
        whole = 1.8e19;
    uint64_t total = (uint64_t)whole;
    uint64_t days = total / 86400U;
    unsigned hh = (unsigned)((total % 86400U) / 3600U);
    unsigned mm = (unsigned)((total % 3600U) / 60U);
    unsigned ss = (unsigned)(total % 60U);
    if (days > 0)
        snprintf(buf, sz, "%" PRIu64 "d %02u:%02u:%02u", days, hh, mm, ss);
    else
        snprintf(buf, sz, "%02u:%02u:%02u", hh, mm, ss);
}

void report_format_bitrate(double bits_per_sec, char *buf, size_t sz)
{
    if (buf == NULL || sz == 0)
        return;
    if (!isfinite(bits_per_sec) || bits_per_sec < 0.0)
        bits_per_sec = 0.0;
    if (bits_per_sec >= 1e9)
        snprintf(buf, sz, "%.2f Gbps", bits_per_sec / 1e9);
    else if (bits_per_sec >= 1e6)
        snprintf(buf, sz, "%.2f Mbps", bits_per_sec / 1e6);
    else if (bits_per_sec >= 1e3)
        snprintf(buf, sz, "%.1f kbps", bits_per_sec / 1e3);
    else
        snprintf(buf, sz, "%.0f bps", bits_per_sec);
}

static void draw_rounded_rect(cairo_t *cr, double x, double y, double w, double h, double r)
{
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -M_PI / 2.0, 0.0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0.0, M_PI / 2.0);
    cairo_arc(cr, x + r, y + h - r, r, M_PI / 2.0, M_PI);
    cairo_arc(cr, x + r, y + r, r, M_PI, 3.0 * M_PI / 2.0);
    cairo_close_path(cr);
}

/* -------------------------------------------------------------------
 * Text Fitting Helpers
 *
 * All table cells and single-line labels go through show_text_fit(), which
 * guarantees the rendered string never exceeds its column budget: if the
 * text is too wide it is cut and suffixed with "...". Multi-line text goes
 * through wrap_text(), which also hard-breaks unbroken tokens (paths,
 * IPv6 addresses, identifiers) that are wider than a full line.
 * ------------------------------------------------------------------- */

#define RPT_TEXT_BUF   512   /**< Scratch buffer for measured strings. */
#define RPT_LINE_BUF   256   /**< Capacity of one wrapped line. */
#define RPT_CELL_PAD   6.0   /**< Horizontal gap kept free before the next column. */
#define RPT_ELLIPSIS   "..."
#define RPT_CONTENT_W  (REPORT_PAGE_WIDTH - 2.0 * REPORT_PAGE_MARGIN)
#define RPT_PROTO_ROWS 6     /**< Protocol table rows, Total included. */

/** Rendered width of @p s in the current font (max of advance and ink box). */
static double text_width(cairo_t *cr, const char *s)
{
    cairo_text_extents_t ext;
    cairo_text_extents(cr, s, &ext);
    double ink_right = ext.x_bearing + ext.width;
    return (ink_right > ext.x_advance) ? ink_right : ext.x_advance;
}

/** Width of the first @p n bytes of @p s followed by @p suffix. */
static double prefix_width(cairo_t *cr, const char *s, size_t n, const char *suffix)
{
    char buf[RPT_TEXT_BUF];
    size_t slen = strlen(suffix);
    if (n + slen >= sizeof(buf)) {
        n = sizeof(buf) - 1 - slen;
    }
    memcpy(buf, s, n);
    memcpy(buf + n, suffix, slen);
    buf[n + slen] = '\0';
    return text_width(cr, buf);
}

/** Move @p n back so it does not split a UTF-8 multi-byte sequence. */
static size_t utf8_floor(const char *s, size_t n)
{
    while (n > 0 && ((unsigned char)s[n] & 0xC0) == 0x80) {
        n--;
    }
    return n;
}

/**
 * Largest byte count n <= @p len such that s[0..n) + @p suffix fits in
 * @p max_w. Binary search: glyph advances are non-negative, so width is
 * monotonic in n.
 */
static size_t fit_prefix_len(cairo_t *cr, const char *s, size_t len,
                             const char *suffix, double max_w)
{
    size_t lo = 0, hi = len;
    while (lo < hi) {
        size_t mid = lo + (hi - lo + 1) / 2;
        if (prefix_width(cr, s, mid, suffix) <= max_w) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    return utf8_floor(s, lo);
}

/**
 * Copy @p text into @p out, truncating with "..." so its width in the
 * current font is <= @p max_w. Produces "" if not even "..." fits.
 */
static void fit_text(cairo_t *cr, const char *text, double max_w, char *out, size_t out_sz)
{
    if (out_sz == 0) {
        return;
    }
    out[0] = '\0';
    if (!text || max_w <= 0.0 || out_sz < sizeof(RPT_ELLIPSIS)) {
        return;
    }

    size_t len = strlen(text);
    if (len < out_sz && len < RPT_TEXT_BUF && text_width(cr, text) <= max_w) {
        memcpy(out, text, len + 1);
        return;
    }
    if (text_width(cr, RPT_ELLIPSIS) > max_w) {
        return;
    }

    size_t cap = PCAPSTAT_MIN(out_sz, (size_t)RPT_TEXT_BUF) - sizeof(RPT_ELLIPSIS);
    if (len > cap) {
        len = utf8_floor(text, cap);
    }
    size_t n = fit_prefix_len(cr, text, len, RPT_ELLIPSIS, max_w);
    while (n > 0 && (text[n - 1] == ' ' || text[n - 1] == ',')) {
        n--;
    }
    memcpy(out, text, n);
    memcpy(out + n, RPT_ELLIPSIS, sizeof(RPT_ELLIPSIS));
}

/** Draw @p text at (@p x, @p y), truncated with "..." to fit @p max_w. */
static void show_text_fit(cairo_t *cr, double x, double y, double max_w, const char *text)
{
    char buf[RPT_TEXT_BUF];
    fit_text(cr, text, max_w, buf, sizeof(buf));
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, buf);
}

/**
 * Draw @p text shrinking the font from @p size down to @p min_size (0.5 pt
 * steps) until it fits @p max_w; truncates with "..." if still too wide.
 * Leaves the font size modified (callers wrap in cairo_save/restore).
 */
static void show_text_shrink_fit(cairo_t *cr, double x, double y, double max_w,
                                 double size, double min_size, const char *text)
{
    cairo_set_font_size(cr, size);
    while (size - 0.5 >= min_size && text_width(cr, text) > max_w) {
        size -= 0.5;
        cairo_set_font_size(cr, size);
    }
    show_text_fit(cr, x, y, max_w, text);
}

/** Right edge budget for a column starting at @p col_x when the next starts at @p next_x. */
static double col_w(double col_x, double next_x)
{
    return next_x - col_x - RPT_CELL_PAD;
}

/**
 * @brief Word-wrap @p text into at most @p max_lines lines of width <= @p max_width.
 *
 * Breaks on spaces/tabs and honours '\n'. A token wider than a whole line is
 * hard-broken at the largest fitting prefix (UTF-8 safe). If the text does
 * not fit in @p max_lines, the last line is ended with "...".
 *
 * @return Number of lines written to @p lines.
 */
static size_t wrap_text(cairo_t *cr, const char *text, double max_width,
                        char lines[][RPT_LINE_BUF], size_t max_lines)
{
    if (!cr || !text || max_width <= 0.0 || max_lines == 0) {
        return 0;
    }

    size_t n = 0;
    char cur[RPT_LINE_BUF];
    size_t cur_len = 0;
    bool truncated = false;
    const char *p = text;
    cur[0] = '\0';

#define WRAP_COMMIT()                                   \
    do {                                                \
        if (n == max_lines) {                           \
            truncated = true;                           \
            goto done;                                  \
        }                                               \
        memcpy(lines[n++], cur, cur_len + 1);           \
        cur_len = 0;                                    \
        cur[0] = '\0';                                  \
    } while (0)

    while (*p) {
        if (*p == ' ' || *p == '\t') {
            p++;
            continue;
        }
        if (*p == '\n') {
            WRAP_COMMIT();
            p++;
            continue;
        }

        const char *w = p;
        size_t wlen = 0;
        while (w[wlen] && w[wlen] != ' ' && w[wlen] != '\t' && w[wlen] != '\n') {
            wlen++;
        }
        p = w + wlen;

        while (wlen > 0) {
            if (cur_len > 0) {
                if (cur_len + 1 + wlen < RPT_LINE_BUF) {
                    char cand[RPT_LINE_BUF];
                    memcpy(cand, cur, cur_len);
                    cand[cur_len] = ' ';
                    memcpy(cand + cur_len + 1, w, wlen);
                    cand[cur_len + 1 + wlen] = '\0';
                    if (text_width(cr, cand) <= max_width) {
                        memcpy(cur, cand, cur_len + 1 + wlen + 1);
                        cur_len += 1 + wlen;
                        break;
                    }
                }
                WRAP_COMMIT();
            }

            /* Line is empty: place the token, hard-breaking it if too wide. */
            size_t take = PCAPSTAT_MIN(wlen, (size_t)RPT_LINE_BUF - 1);
            take = utf8_floor(w, take);
            if (take == 0 || prefix_width(cr, w, take, "") > max_width) {
                take = fit_prefix_len(cr, w, take, "", max_width);
                if (take == 0) {
                    /* Not even one glyph fits: emit one character anyway. */
                    take = 1;
                    while (take < wlen && ((unsigned char)w[take] & 0xC0) == 0x80) {
                        take++;
                    }
                }
            }
            memcpy(cur, w, take);
            cur[take] = '\0';
            cur_len = take;
            w += take;
            wlen -= take;
            if (wlen > 0) {
                WRAP_COMMIT();
            }
        }
    }

    if (cur_len > 0) {
        WRAP_COMMIT();
    }

done:
#undef WRAP_COMMIT
    if (truncated && n > 0) {
        char tmp[RPT_LINE_BUF + sizeof(RPT_ELLIPSIS)];
        snprintf(tmp, sizeof(tmp), "%s%s", lines[n - 1], RPT_ELLIPSIS);
        fit_text(cr, tmp, max_width, lines[n - 1], RPT_LINE_BUF);
    }
    return n;
}

/* -------------------------------------------------------------------
 * Header and Footer Layout
 * ------------------------------------------------------------------- */

static void draw_page_header(cairo_t *cr)
{
    cairo_save(cr);
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 8.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    char ver_buf[64];
    snprintf(ver_buf, sizeof(ver_buf), "Version %s", PCAPSTAT_VERSION);
    double ver_w = text_width(cr, ver_buf);
    cairo_move_to(cr, REPORT_PAGE_WIDTH - REPORT_PAGE_MARGIN - ver_w, 36.0);
    cairo_show_text(cr, ver_buf);
    show_text_fit(cr, REPORT_PAGE_MARGIN, 36.0, RPT_CONTENT_W - ver_w - 2.0 * RPT_CELL_PAD,
                  "pcapstat - Network Traffic Analysis Report");

    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.75);
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 44.0);
    cairo_line_to(cr, REPORT_PAGE_WIDTH - REPORT_PAGE_MARGIN, 44.0);
    cairo_stroke(cr);
    cairo_restore(cr);
}

static void draw_page_footer(cairo_t *cr, int page_num, int total_pages, const char *timestamp_str)
{
    cairo_save(cr);
    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.75);
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 802.0);
    cairo_line_to(cr, REPORT_PAGE_WIDTH - REPORT_PAGE_MARGIN, 802.0);
    cairo_stroke(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 8.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    char page_buf[64];
    snprintf(page_buf, sizeof(page_buf), "Page %d of %d", page_num, total_pages);
    double page_w = text_width(cr, page_buf);
    cairo_move_to(cr, REPORT_PAGE_WIDTH - REPORT_PAGE_MARGIN - page_w, 816.0);
    cairo_show_text(cr, page_buf);
    show_text_fit(cr, REPORT_PAGE_MARGIN, 816.0, RPT_CONTENT_W - page_w - 2.0 * RPT_CELL_PAD,
                  timestamp_str);
    cairo_restore(cr);
}

/* -------------------------------------------------------------------
 * Page 1: Executive Summary & KPI Cards/Tables
 * ------------------------------------------------------------------- */

static void render_kpi_card(cairo_t *cr, double x, double y, double w, double h,
                            const char *title, const char *val, const char *subtext,
                            double val_r, double val_g, double val_b)
{
    cairo_save(cr);

    /* Background and border */
    draw_rounded_rect(cr, x, y, w, h, 4.0);
    cairo_set_source_rgb(cr, RPT_COLOR_BG_CARD_R, RPT_COLOR_BG_CARD_G, RPT_COLOR_BG_CARD_B);
    cairo_fill_preserve(cr);
    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.75);
    cairo_stroke(cr);

    /* Card Title */
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    double inner_w = w - 20.0;
    show_text_fit(cr, x + 10.0, y + 16.0, inner_w, title);

    /* Primary Value: shrink font before truncating so numbers stay readable */
    cairo_set_source_rgb(cr, val_r, val_g, val_b);
    show_text_shrink_fit(cr, x + 10.0, y + 38.0, inner_w, 14.5, 9.0, val);

    /* Subtext */
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 8.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    show_text_fit(cr, x + 10.0, y + 54.0, inner_w, subtext);

    cairo_restore(cr);
}

static void render_page1_executive_summary(cairo_t *cr,
                                          const cli_config_t *cfg,
                                          const stats_ctx_t *stats,
                                          const anomaly_list_t *anomalies)
{
    /* Document Title */
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 20.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, REPORT_PAGE_MARGIN, 68.0, RPT_CONTENT_W, "Executive Summary & Traffic Telemetry");

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    show_text_fit(cr, REPORT_PAGE_MARGIN, 82.0, RPT_CONTENT_W, "Automated network traffic inspection, protocol metrics, and baseline security assessment");

    /* Scope & Input Card */
    double card_x = REPORT_PAGE_MARGIN;
    double card_y = 96.0;
    double card_w = REPORT_PAGE_WIDTH - 2.0 * REPORT_PAGE_MARGIN;
    double card_h = 58.0;

    draw_rounded_rect(cr, card_x, card_y, card_w, card_h, 4.0);
    cairo_set_source_rgb(cr, RPT_COLOR_BG_CARD_R, RPT_COLOR_BG_CARD_G, RPT_COLOR_BG_CARD_B);
    cairo_fill_preserve(cr);
    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.75);
    cairo_stroke(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 9.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, card_x + 12.0, card_y + 18.0, 92.0, "Capture Sources:");

    /* Format input files string */
    char files_summary[512] = {0};
    if (cfg && cfg->input_count > 0 && cfg->input_files) {
        for (size_t i = 0; i < cfg->input_count; i++) {
            if (i > 0) {
                strncat(files_summary, ", ", sizeof(files_summary) - strlen(files_summary) - 1);
            }
            if (strlen(files_summary) + strlen(cfg->input_files[i]) + 10 < sizeof(files_summary)) {
                strncat(files_summary, cfg->input_files[i], sizeof(files_summary) - strlen(files_summary) - 1);
            } else {
                strncat(files_summary, "...", sizeof(files_summary) - strlen(files_summary) - 1);
                break;
            }
        }
    } else {
        snprintf(files_summary, sizeof(files_summary), "(none)");
    }

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 8.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    show_text_fit(cr, card_x + 110.0, card_y + 18.0, card_w - 110.0 - 12.0, files_summary);

    /* Second line inside capture box */
    char meta_line[256];
    char pkts_str[32];
    char dur_buf[48];
    const size_t n_flows = stats->flows_ht ? ht_count(stats->flows_ht) : 0;
    const size_t n_hosts = stats->hosts_ht ? ht_count(stats->hosts_ht) : 0;
    format_count_commas(stats->total_packets, pkts_str, sizeof(pkts_str));
    report_format_duration(stats->duration_sec, dur_buf, sizeof(dur_buf));
    snprintf(meta_line, sizeof(meta_line),
             "Files Processed: %" PRIu64 "  |  Packets: %s  |  Duration: %s  |  Active Flows: %zu  |  Unique Hosts: %zu",
             stats->files_processed, pkts_str, dur_buf, n_flows, n_hosts);
    show_text_fit(cr, card_x + 12.0, card_y + 36.0, card_w - 24.0, meta_line);

    /* Count anomaly severities */
    uint32_t n_crit = 0, n_warn = 0, n_info = 0;
    if (anomalies) {
        for (size_t i = 0; i < anomalies->count; i++) {
            if (anomalies->items[i].severity == ANOMALY_CRITICAL) n_crit++;
            else if (anomalies->items[i].severity == ANOMALY_WARNING) n_warn++;
            else n_info++;
        }
    }

    /* KPI Cards (3 cols x 2 rows) */
    double kpi_w = (card_w - 24.0) / 3.0;
    double kpi_h = 62.0;
    double row1_y = 166.0;
    double row2_y = 236.0;

    /* Card 1: Total Volume */
    char vol_buf[32];
    format_bytes(stats->total_bytes, vol_buf, sizeof(vol_buf));
    char pkts_sub[64];
    snprintf(pkts_sub, sizeof(pkts_sub), "%s total packets", pkts_str);
    render_kpi_card(cr, card_x, row1_y, kpi_w, kpi_h,
                    "TOTAL TRAFFIC VOLUME", vol_buf, pkts_sub,
                    RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

    /* Card 2: Capture Duration & Rates (avg_bps is bits per second). */
    char rate_sub[64];
    char bitrate_buf[32];
    report_format_bitrate(stats->avg_bps, bitrate_buf, sizeof(bitrate_buf));
    snprintf(rate_sub, sizeof(rate_sub), "%.1f pps | %s", stats->avg_pps, bitrate_buf);
    render_kpi_card(cr, card_x + kpi_w + 12.0, row1_y, kpi_w, kpi_h,
                    "CAPTURE DURATION & RATE", dur_buf, rate_sub,
                    RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

    /* Card 3: Security Findings */
    char anom_val[32];
    snprintf(anom_val, sizeof(anom_val), "%zu Findings", anomalies ? anomalies->count : 0);
    char anom_sub[64];
    snprintf(anom_sub, sizeof(anom_sub), "%u Crit | %u Warn | %u Info", n_crit, n_warn, n_info);
    double anom_r = (n_crit > 0) ? RPT_COLOR_CRIT_R : ((n_warn > 0) ? RPT_COLOR_WARN_R : RPT_COLOR_OK_R);
    double anom_g = (n_crit > 0) ? RPT_COLOR_CRIT_G : ((n_warn > 0) ? RPT_COLOR_WARN_G : RPT_COLOR_OK_G);
    double anom_b = (n_crit > 0) ? RPT_COLOR_CRIT_B : ((n_warn > 0) ? RPT_COLOR_WARN_B : RPT_COLOR_OK_B);
    render_kpi_card(cr, card_x + 2.0 * (kpi_w + 12.0), row1_y, kpi_w, kpi_h,
                    "SECURITY ASSESSMENT", anom_val, anom_sub, anom_r, anom_g, anom_b);

    /* Card 4: Protocol Share */
    double tcp_pct = stats->total_packets ? (100.0 * (double)stats->tcp_packets / (double)stats->total_packets) : 0.0;
    double udp_pct = stats->total_packets ? (100.0 * (double)stats->udp_packets / (double)stats->total_packets) : 0.0;
    char proto_val[32];
    snprintf(proto_val, sizeof(proto_val), "TCP %.1f%% | UDP %.1f%%", tcp_pct, udp_pct);
    char proto_sub[64];
    snprintf(proto_sub, sizeof(proto_sub),
             "Other %" PRIu64 " | Non-IP %" PRIu64 " | Malformed %" PRIu64,
             stats->other_packets, stats->non_ip_packets, stats->malformed_packets);
    render_kpi_card(cr, card_x, row2_y, kpi_w, kpi_h,
                    "TRANSPORT PROTOCOL SHARE", proto_val, proto_sub,
                    RPT_COLOR_PRIMARY_R, RPT_COLOR_PRIMARY_G, RPT_COLOR_PRIMARY_B);

    /* Card 5: Endpoints & Flows */
    char sess_val[32];
    snprintf(sess_val, sizeof(sess_val), "%zu Flows", n_flows);
    char sess_sub[64];
    snprintf(sess_sub, sizeof(sess_sub), "%zu unique endpoints active", n_hosts);
    render_kpi_card(cr, card_x + kpi_w + 12.0, row2_y, kpi_w, kpi_h,
                    "NETWORK SESSIONS", sess_val, sess_sub,
                    RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

    /* Card 6: TCP Health. Global counters cover every flow (not only the
     * top-N); out-of-order segments are reordering, not retransmissions. */
    char tcp_val[32];
    const uint64_t total_retrans = stats->tcp_retransmissions;
    snprintf(tcp_val, sizeof(tcp_val), "%" PRIu64 " Retrans", total_retrans);
    char tcp_sub[96];
    snprintf(tcp_sub, sizeof(tcp_sub),
             "Out-of-order: %" PRIu64 " | SYN: %" PRIu64 " | RST: %" PRIu64,
             stats->tcp_out_of_order, stats->syn, stats->rst);
    render_kpi_card(cr, card_x + 2.0 * (kpi_w + 12.0), row2_y, kpi_w, kpi_h,
                    "TCP RELIABILITY & FLAGS", tcp_val, tcp_sub,
                    (total_retrans > 0 ? RPT_COLOR_WARN_R : RPT_COLOR_TEXT_MAIN_R),
                    (total_retrans > 0 ? RPT_COLOR_WARN_G : RPT_COLOR_TEXT_MAIN_G),
                    (total_retrans > 0 ? RPT_COLOR_WARN_B : RPT_COLOR_TEXT_MAIN_B));

    /* ---------------------------------------------------------------
     * Protocol Breakdown Table
     * --------------------------------------------------------------- */
    double tbl_y = 316.0;
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 11.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, card_x, tbl_y, RPT_CONTENT_W, "Global Protocol & Wire Volume Breakdown");

    tbl_y += 10.0;
    /* Header Row */
    cairo_set_source_rgb(cr, RPT_COLOR_TH_BG_R, RPT_COLOR_TH_BG_G, RPT_COLOR_TH_BG_B);
    cairo_rectangle(cr, card_x, tbl_y, card_w, 18.0);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.5);
    cairo_rectangle(cr, card_x, tbl_y, card_w, 18.0);
    cairo_stroke(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, card_x + 8.0, tbl_y + 12.5, col_w(8.0, 160.0), "Traffic Category");
    show_text_fit(cr, card_x + 160.0, tbl_y + 12.5, col_w(160.0, 245.0), "Packets");
    show_text_fit(cr, card_x + 245.0, tbl_y + 12.5, col_w(245.0, 335.0), "Packet Share");
    show_text_fit(cr, card_x + 335.0, tbl_y + 12.5, col_w(335.0, 440.0), "Volume (Bytes)");
    show_text_fit(cr, card_x + 440.0, tbl_y + 12.5, col_w(440.0, card_w), "Volume Share");

    struct {
        const char *label;
        uint64_t pkts;
        uint64_t bytes;
    } proto_rows[RPT_PROTO_ROWS] = {
        {"TCP", stats->tcp_packets, stats->tcp_bytes},
        {"UDP", stats->udp_packets, stats->udp_bytes},
        {"Other IP", stats->other_packets, 0},
        {"Non-IP frames (ARP/LLDP/...)", stats->non_ip_packets, 0},
        {"Malformed", stats->malformed_packets, 0},
        {"Total", stats->total_packets, stats->total_bytes}
    };
    const int total_row = RPT_PROTO_ROWS - 1;

    double cur_y = tbl_y + 18.0;
    for (int i = 0; i < RPT_PROTO_ROWS; i++) {
        if (i % 2 == 1 && i != total_row) {
            cairo_set_source_rgb(cr, RPT_COLOR_ZEBRA_R, RPT_COLOR_ZEBRA_G, RPT_COLOR_ZEBRA_B);
            cairo_rectangle(cr, card_x, cur_y, card_w, 16.0);
            cairo_fill(cr);
        } else if (i == total_row) {
            cairo_set_source_rgb(cr, RPT_COLOR_TH_BG_R, RPT_COLOR_TH_BG_G, RPT_COLOR_TH_BG_B);
            cairo_rectangle(cr, card_x, cur_y, card_w, 17.0);
            cairo_fill(cr);
        }

        cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
        cairo_set_line_width(cr, 0.5);
        cairo_move_to(cr, card_x, cur_y + 16.0);
        cairo_line_to(cr, card_x + card_w, cur_y + 16.0);
        cairo_stroke(cr);

        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, (i == total_row) ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 8.5);
        cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

        show_text_fit(cr, card_x + 8.0, cur_y + 11.5, col_w(8.0, 160.0), proto_rows[i].label);

        char p_str[32], b_str[32], ps_str[32], bs_str[32];
        format_count_commas(proto_rows[i].pkts, p_str, sizeof(p_str));
        double p_share = stats->total_packets ? (100.0 * (double)proto_rows[i].pkts / (double)stats->total_packets) : 0.0;
        snprintf(ps_str, sizeof(ps_str), "%.1f %%", p_share);

        if (proto_rows[i].bytes > 0 || i < 2 || i == total_row) {
            format_bytes(proto_rows[i].bytes, b_str, sizeof(b_str));
            double b_share = stats->total_bytes ? (100.0 * (double)proto_rows[i].bytes / (double)stats->total_bytes) : 0.0;
            snprintf(bs_str, sizeof(bs_str), "%.1f %%", b_share);
        } else {
            snprintf(b_str, sizeof(b_str), "N/A");
            snprintf(bs_str, sizeof(bs_str), "N/A");
        }

        show_text_fit(cr, card_x + 160.0, cur_y + 11.5, col_w(160.0, 245.0), p_str);
        show_text_fit(cr, card_x + 245.0, cur_y + 11.5, col_w(245.0, 335.0), ps_str);
        show_text_fit(cr, card_x + 335.0, cur_y + 11.5, col_w(335.0, 440.0), b_str);
        show_text_fit(cr, card_x + 440.0, cur_y + 11.5, col_w(440.0, card_w), bs_str);

        cur_y += (i == total_row) ? 17.0 : 16.0;
    }

    /* ---------------------------------------------------------------
     * TCP Flags Table
     * --------------------------------------------------------------- */
    double flag_y = cur_y + 20.0;
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 11.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, card_x, flag_y, RPT_CONTENT_W, "TCP Flags Telemetry & Connection Behavior");

    flag_y += 10.0;
    cairo_set_source_rgb(cr, RPT_COLOR_TH_BG_R, RPT_COLOR_TH_BG_G, RPT_COLOR_TH_BG_B);
    cairo_rectangle(cr, card_x, flag_y, card_w, 18.0);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.5);
    cairo_rectangle(cr, card_x, flag_y, card_w, 18.0);
    cairo_stroke(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, card_x + 8.0, flag_y + 12.5, col_w(8.0, 140.0), "TCP Flag / Condition");
    show_text_fit(cr, card_x + 140.0, flag_y + 12.5, col_w(140.0, 205.0), "Count");
    show_text_fit(cr, card_x + 205.0, flag_y + 12.5, col_w(205.0, 280.0), "% of TCP");
    show_text_fit(cr, card_x + 280.0, flag_y + 12.5, col_w(280.0, card_w), "Health & Diagnostic Signal");

    struct {
        const char *flag;
        uint64_t count;
        const char *diag;
    } flags[8] = {
        {"SYN (Pure)", stats->syn, "Initial handshake requests (outbound sessions)"},
        {"SYN-ACK", stats->syn_ack, "Server handshake responses (established sessions)"},
        {"ACK", stats->ack, "Established data transfers and acknowledgments"},
        {"FIN", stats->fin, "Graceful connection terminations"},
        {"RST", stats->rst, "Immediate resets (connection refusals or aborts)"},
        {"PSH", stats->psh, "Push data segments to application layer"},
        {"URG", stats->urg, "Urgent pointer notifications"},
        {"Suspicious (Null/Xmas/etc)",
         stats->null_scan_pkts + stats->xmas_scan_pkts + stats->syn_fin_pkts + stats->syn_rst_pkts,
         "Evasion probes and malformed flag signatures"}
    };

    cur_y = flag_y + 18.0;
    for (int i = 0; i < 8; i++) {
        if (i % 2 == 1) {
            cairo_set_source_rgb(cr, RPT_COLOR_ZEBRA_R, RPT_COLOR_ZEBRA_G, RPT_COLOR_ZEBRA_B);
            cairo_rectangle(cr, card_x, cur_y, card_w, 15.0);
            cairo_fill(cr);
        }

        cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
        cairo_set_line_width(cr, 0.5);
        cairo_move_to(cr, card_x, cur_y + 15.0);
        cairo_line_to(cr, card_x + card_w, cur_y + 15.0);
        cairo_stroke(cr);

        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 8.0);
        cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

        show_text_fit(cr, card_x + 8.0, cur_y + 11.0, col_w(8.0, 140.0), flags[i].flag);

        char c_str[32], s_str[32];
        format_count_commas(flags[i].count, c_str, sizeof(c_str));
        double tcp_share = stats->tcp_packets ? (100.0 * (double)flags[i].count / (double)stats->tcp_packets) : 0.0;
        snprintf(s_str, sizeof(s_str), "%.1f %%", tcp_share);

        show_text_fit(cr, card_x + 140.0, cur_y + 11.0, col_w(140.0, 205.0), c_str);
        show_text_fit(cr, card_x + 205.0, cur_y + 11.0, col_w(205.0, 280.0), s_str);

        if (i == 7 && flags[i].count > 0) {
            cairo_set_source_rgb(cr, RPT_COLOR_CRIT_R, RPT_COLOR_CRIT_G, RPT_COLOR_CRIT_B);
        } else if (i == 4 && tcp_share > 10.0 && stats->tcp_packets >= 30) {
            cairo_set_source_rgb(cr, RPT_COLOR_WARN_R, RPT_COLOR_WARN_G, RPT_COLOR_WARN_B);
        } else {
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
        }
        show_text_fit(cr, card_x + 280.0, cur_y + 11.0, col_w(280.0, card_w), flags[i].diag);

        cur_y += 15.0;
    }
}

/* -------------------------------------------------------------------
 * Page 2: Top Talkers, Ports/Services, and Flows
 * ------------------------------------------------------------------- */

static void render_page2_traffic_characteristics(cairo_t *cr, const stats_ctx_t *stats)
{
    /* Page Title */
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 18.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, REPORT_PAGE_MARGIN, 68.0, RPT_CONTENT_W, "Traffic Characteristics & Top Rankings");

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    show_text_fit(cr, REPORT_PAGE_MARGIN, 82.0, RPT_CONTENT_W, "Detailed top-10 rankings for endpoints, destination services, and active network flows");

    double card_x = REPORT_PAGE_MARGIN;
    double card_w = REPORT_PAGE_WIDTH - 2.0 * REPORT_PAGE_MARGIN;

    /* ---------------------------------------------------------------
     * Table 1: Top 10 IP Talkers (Hosts)
     * --------------------------------------------------------------- */
    double tbl1_y = 104.0;
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 10.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, card_x, tbl1_y, RPT_CONTENT_W, "1. Top 10 IP Talkers (by Total Wire Volume)");

    tbl1_y += 6.0;
    cairo_set_source_rgb(cr, RPT_COLOR_TH_BG_R, RPT_COLOR_TH_BG_G, RPT_COLOR_TH_BG_B);
    cairo_rectangle(cr, card_x, tbl1_y, card_w, 16.0);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.5);
    cairo_rectangle(cr, card_x, tbl1_y, card_w, 16.0);
    cairo_stroke(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

    show_text_fit(cr, card_x + 6.0, tbl1_y + 11.5, col_w(6.0, 24.0), "#");
    show_text_fit(cr, card_x + 24.0, tbl1_y + 11.5, col_w(24.0, 175.0), "IP Address");
    show_text_fit(cr, card_x + 175.0, tbl1_y + 11.5, col_w(175.0, 235.0), "TX Pkts");
    show_text_fit(cr, card_x + 235.0, tbl1_y + 11.5, col_w(235.0, 300.0), "TX Volume");
    show_text_fit(cr, card_x + 300.0, tbl1_y + 11.5, col_w(300.0, 360.0), "RX Pkts");
    show_text_fit(cr, card_x + 360.0, tbl1_y + 11.5, col_w(360.0, 425.0), "RX Volume");
    show_text_fit(cr, card_x + 425.0, tbl1_y + 11.5, col_w(425.0, card_w), "Total Volume");

    const host_stats_t *hosts[10];
    size_t host_n = stats_top_hosts(stats, hosts, 10);
    double cur_y = tbl1_y + 16.0;

    for (size_t i = 0; i < 10; i++) {
        if (i % 2 == 1) {
            cairo_set_source_rgb(cr, RPT_COLOR_ZEBRA_R, RPT_COLOR_ZEBRA_G, RPT_COLOR_ZEBRA_B);
            cairo_rectangle(cr, card_x, cur_y, card_w, 14.0);
            cairo_fill(cr);
        }
        cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
        cairo_set_line_width(cr, 0.5);
        cairo_move_to(cr, card_x, cur_y + 14.0);
        cairo_line_to(cr, card_x + card_w, cur_y + 14.0);
        cairo_stroke(cr);

        if (i < host_n) {
            const host_stats_t *h = hosts[i];
            char ip_str[64];
            parser_format_ip(h->ip_version, h->ip, ip_str, sizeof(ip_str));

            char rank_str[8], tx_p[32], tx_b[32], rx_p[32], rx_b[32], tot_b[32];
            snprintf(rank_str, sizeof(rank_str), "%zu", i + 1);
            format_count_commas(h->tx_packets, tx_p, sizeof(tx_p));
            format_bytes(h->tx_bytes, tx_b, sizeof(tx_b));
            format_count_commas(h->rx_packets, rx_p, sizeof(rx_p));
            format_bytes(h->rx_bytes, rx_b, sizeof(rx_b));
            format_bytes(h->tx_bytes + h->rx_bytes, tot_b, sizeof(tot_b));

            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 8.0);
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

            show_text_fit(cr, card_x + 6.0, cur_y + 10.5, col_w(6.0, 24.0), rank_str);
            show_text_fit(cr, card_x + 24.0, cur_y + 10.5, col_w(24.0, 175.0), ip_str);
            show_text_fit(cr, card_x + 175.0, cur_y + 10.5, col_w(175.0, 235.0), tx_p);
            show_text_fit(cr, card_x + 235.0, cur_y + 10.5, col_w(235.0, 300.0), tx_b);
            show_text_fit(cr, card_x + 300.0, cur_y + 10.5, col_w(300.0, 360.0), rx_p);
            show_text_fit(cr, card_x + 360.0, cur_y + 10.5, col_w(360.0, 425.0), rx_b);
            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
            show_text_fit(cr, card_x + 425.0, cur_y + 10.5, col_w(425.0, card_w), tot_b);
        } else {
            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 7.5);
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
            show_text_fit(cr, card_x + 24.0, cur_y + 10.5, col_w(24.0, 175.0), "-");
        }
        cur_y += 14.0;
    }

    /* ---------------------------------------------------------------
     * Table 2: Top 10 Destination Ports & Services
     * --------------------------------------------------------------- */
    double tbl2_y = cur_y + 18.0;
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 10.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, card_x, tbl2_y, RPT_CONTENT_W, "2. Top 10 Destination Ports & Services (by Packet Count)");

    tbl2_y += 6.0;
    cairo_set_source_rgb(cr, RPT_COLOR_TH_BG_R, RPT_COLOR_TH_BG_G, RPT_COLOR_TH_BG_B);
    cairo_rectangle(cr, card_x, tbl2_y, card_w, 16.0);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.5);
    cairo_rectangle(cr, card_x, tbl2_y, card_w, 16.0);
    cairo_stroke(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

    show_text_fit(cr, card_x + 6.0, tbl2_y + 11.5, col_w(6.0, 30.0), "#");
    show_text_fit(cr, card_x + 30.0, tbl2_y + 11.5, col_w(30.0, 75.0), "Proto");
    show_text_fit(cr, card_x + 75.0, tbl2_y + 11.5, col_w(75.0, 130.0), "Port");
    show_text_fit(cr, card_x + 130.0, tbl2_y + 11.5, col_w(130.0, 245.0), "Service Name");
    show_text_fit(cr, card_x + 245.0, tbl2_y + 11.5, col_w(245.0, 345.0), "Packets");
    show_text_fit(cr, card_x + 345.0, tbl2_y + 11.5, col_w(345.0, 445.0), "Wire Volume");
    show_text_fit(cr, card_x + 445.0, tbl2_y + 11.5, col_w(445.0, card_w), "% of Packets");

    const port_stats_t *ports[10];
    size_t port_n = stats_top_ports(stats, ports, 10);
    cur_y = tbl2_y + 16.0;

    for (size_t i = 0; i < 10; i++) {
        if (i % 2 == 1) {
            cairo_set_source_rgb(cr, RPT_COLOR_ZEBRA_R, RPT_COLOR_ZEBRA_G, RPT_COLOR_ZEBRA_B);
            cairo_rectangle(cr, card_x, cur_y, card_w, 14.0);
            cairo_fill(cr);
        }
        cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
        cairo_set_line_width(cr, 0.5);
        cairo_move_to(cr, card_x, cur_y + 14.0);
        cairo_line_to(cr, card_x + card_w, cur_y + 14.0);
        cairo_stroke(cr);

        if (i < port_n) {
            const port_stats_t *p = ports[i];
            const char *proto_name = (p->proto == IPPROTO_TCP) ? "TCP" : (p->proto == IPPROTO_UDP) ? "UDP" : "OTHER";
            const char *svc_name = stats_port_service_name(p->proto, p->dst_port);

            char rank_str[8], port_str[16], p_str[32], b_str[32], share_str[32];
            snprintf(rank_str, sizeof(rank_str), "%zu", i + 1);
            snprintf(port_str, sizeof(port_str), "%u", p->dst_port);
            format_count_commas(p->packets, p_str, sizeof(p_str));
            format_bytes(p->bytes, b_str, sizeof(b_str));
            double sh = stats->total_packets ? (100.0 * (double)p->packets / (double)stats->total_packets) : 0.0;
            snprintf(share_str, sizeof(share_str), "%.1f %%", sh);

            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 8.0);
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

            show_text_fit(cr, card_x + 6.0, cur_y + 10.5, col_w(6.0, 30.0), rank_str);
            show_text_fit(cr, card_x + 30.0, cur_y + 10.5, col_w(30.0, 75.0), proto_name);
            show_text_fit(cr, card_x + 75.0, cur_y + 10.5, col_w(75.0, 130.0), port_str);
            show_text_fit(cr, card_x + 130.0, cur_y + 10.5, col_w(130.0, 245.0), svc_name);
            show_text_fit(cr, card_x + 245.0, cur_y + 10.5, col_w(245.0, 345.0), p_str);
            show_text_fit(cr, card_x + 345.0, cur_y + 10.5, col_w(345.0, 445.0), b_str);
            show_text_fit(cr, card_x + 445.0, cur_y + 10.5, col_w(445.0, card_w), share_str);
        } else {
            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 7.5);
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
            show_text_fit(cr, card_x + 30.0, cur_y + 10.5, col_w(30.0, 75.0), "-");
        }
        cur_y += 14.0;
    }

    /* ---------------------------------------------------------------
     * Table 3: Top 10 Directional Flows
     * --------------------------------------------------------------- */
    double tbl3_y = cur_y + 18.0;
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 10.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, card_x, tbl3_y, RPT_CONTENT_W, "3. Top 10 Directional 5-Tuple Network Flows");

    tbl3_y += 6.0;
    cairo_set_source_rgb(cr, RPT_COLOR_TH_BG_R, RPT_COLOR_TH_BG_G, RPT_COLOR_TH_BG_B);
    cairo_rectangle(cr, card_x, tbl3_y, card_w, 16.0);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.5);
    cairo_rectangle(cr, card_x, tbl3_y, card_w, 16.0);
    cairo_stroke(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

    show_text_fit(cr, card_x + 6.0, tbl3_y + 11.5, col_w(6.0, 22.0), "#");
    show_text_fit(cr, card_x + 22.0, tbl3_y + 11.5, col_w(22.0, 56.0), "Proto");
    show_text_fit(cr, card_x + 56.0, tbl3_y + 11.5, col_w(56.0, 300.0), "Flow 5-Tuple (Source:Port -> Destination:Port)");
    show_text_fit(cr, card_x + 300.0, tbl3_y + 11.5, col_w(300.0, 352.0), "Packets");
    show_text_fit(cr, card_x + 352.0, tbl3_y + 11.5, col_w(352.0, 408.0), "Volume");
    show_text_fit(cr, card_x + 408.0, tbl3_y + 11.5, col_w(408.0, 452.0), "Retrans");
    show_text_fit(cr, card_x + 452.0, tbl3_y + 11.5, col_w(452.0, card_w), "Duration");

    const flow_stats_t *flows[10];
    size_t flow_n = stats_top_flows(stats, flows, 10);
    cur_y = tbl3_y + 16.0;

    for (size_t i = 0; i < 10; i++) {
        if (i % 2 == 1) {
            cairo_set_source_rgb(cr, RPT_COLOR_ZEBRA_R, RPT_COLOR_ZEBRA_G, RPT_COLOR_ZEBRA_B);
            cairo_rectangle(cr, card_x, cur_y, card_w, 14.0);
            cairo_fill(cr);
        }
        cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
        cairo_set_line_width(cr, 0.5);
        cairo_move_to(cr, card_x, cur_y + 14.0);
        cairo_line_to(cr, card_x + card_w, cur_y + 14.0);
        cairo_stroke(cr);

        if (i < flow_n) {
            const flow_stats_t *f = flows[i];
            const char *proto_name = (f->proto == IPPROTO_TCP) ? "TCP" : (f->proto == IPPROTO_UDP) ? "UDP" : "OTHER";

            char src_ip_str[64], dst_ip_str[64], tuple_str[160];
            parser_format_ip(f->ip_version, f->src_ip, src_ip_str, sizeof(src_ip_str));
            parser_format_ip(f->ip_version, f->dst_ip, dst_ip_str, sizeof(dst_ip_str));
            snprintf(tuple_str, sizeof(tuple_str), "%s:%u -> %s:%u", src_ip_str, f->src_port, dst_ip_str, f->dst_port);

            char rank_str[8], p_str[32], b_str[32], r_str[32], dur_str[32];
            snprintf(rank_str, sizeof(rank_str), "%zu", i + 1);
            format_count_commas(f->packets, p_str, sizeof(p_str));
            format_bytes(f->bytes, b_str, sizeof(b_str));
            snprintf(r_str, sizeof(r_str), "%" PRIu64, f->retransmissions);

            if (f->has_timestamp && f->last_ts >= f->first_ts) {
                snprintf(dur_str, sizeof(dur_str), "%.2f s", f->last_ts - f->first_ts);
            } else {
                snprintf(dur_str, sizeof(dur_str), "-");
            }

            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 7.5);
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

            show_text_fit(cr, card_x + 6.0, cur_y + 10.5, col_w(6.0, 22.0), rank_str);
            show_text_fit(cr, card_x + 22.0, cur_y + 10.5, col_w(22.0, 56.0), proto_name);
            show_text_fit(cr, card_x + 56.0, cur_y + 10.5, col_w(56.0, 300.0), tuple_str);
            show_text_fit(cr, card_x + 300.0, cur_y + 10.5, col_w(300.0, 352.0), p_str);
            show_text_fit(cr, card_x + 352.0, cur_y + 10.5, col_w(352.0, 408.0), b_str);

            if (f->retransmissions > 0) {
                cairo_set_source_rgb(cr, RPT_COLOR_WARN_R, RPT_COLOR_WARN_G, RPT_COLOR_WARN_B);
            }
            show_text_fit(cr, card_x + 408.0, cur_y + 10.5, col_w(408.0, 452.0), r_str);

            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
            show_text_fit(cr, card_x + 452.0, cur_y + 10.5, col_w(452.0, card_w), dur_str);
        } else {
            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 7.5);
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
            show_text_fit(cr, card_x + 56.0, cur_y + 10.5, col_w(56.0, 300.0), "-");
        }
        cur_y += 14.0;
    }
}

/* -------------------------------------------------------------------
 * Page 3: 2x2 Grid Vector Visualizations
 * ------------------------------------------------------------------- */

static int render_page3_visualizations(cairo_t *cr, const stats_ctx_t *stats)
{
    /* Page Title */
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 18.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, REPORT_PAGE_MARGIN, 68.0, RPT_CONTENT_W, "Visualizations & Traffic Patterns");

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    show_text_fit(cr, REPORT_PAGE_MARGIN, 82.0, RPT_CONTENT_W, "Embedded vector charts rendered directly into the PDF coordinate system");

    /* 2x2 Grid Layout Calculations */
    double total_w = REPORT_PAGE_WIDTH - 2.0 * REPORT_PAGE_MARGIN;
    double gap_x = 15.0;
    double chart_w = (total_w - gap_x) / 2.0; /* 250.0 pt */

    double chart_h = 338.0;
    double row1_y = 92.0;
    double row2_y = 446.0;
    double col1_x = REPORT_PAGE_MARGIN;
    double col2_x = REPORT_PAGE_MARGIN + chart_w + gap_x;

    int rc;

    /* Top-Left: Traffic Timeline */
    rc = chart_draw_traffic_timeline(cr, stats, col1_x, row1_y, chart_w, chart_h);
    if (rc != PCAPSTAT_OK) return rc;

    /* Top-Right: Protocol Destination Ports */
    rc = chart_draw_protocol_ports(cr, stats, col2_x, row1_y, chart_w, chart_h);
    if (rc != PCAPSTAT_OK) return rc;

    /* Bottom-Left: Packet Size Distribution */
    rc = chart_draw_packet_sizes(cr, stats, col1_x, row2_y, chart_w, chart_h);
    if (rc != PCAPSTAT_OK) return rc;

    /* Bottom-Right: TCP Flags Distribution */
    rc = chart_draw_tcp_flags(cr, stats, col2_x, row2_y, chart_w, chart_h);
    if (rc != PCAPSTAT_OK) return rc;

    return PCAPSTAT_OK;
}

/* -------------------------------------------------------------------
 * Page 4+: Detected Anomalies with Pagination
 * ------------------------------------------------------------------- */

/* Anomaly table layout, shared by page counting and rendering so the
 * pre-computed "Page X of Y" always matches the pages actually emitted. */
#define ANOM_COL_SEV_X        8.0
#define ANOM_COL_CAT_X        85.0
#define ANOM_COL_DESC_X       225.0
#define ANOM_DESC_W           (RPT_CONTENT_W - ANOM_COL_DESC_X - 8.0)
#define ANOM_DESC_FONT        8.0
#define ANOM_DESC_MAX_LINES   16
#define ANOM_LINE_H           12.0
#define ANOM_HEADER_H         18.0
#define ANOM_FIRST_TABLE_Y    96.0
#define ANOM_CONT_TABLE_Y     60.0
#define ANOM_MAX_Y            785.0

/** Wrap @p a's description into @p lines and return the row height. */
static double anomaly_row_layout(cairo_t *cr, const anomaly_t *a,
                                 char lines[][RPT_LINE_BUF], size_t *nlines)
{
    cairo_save(cr);
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, ANOM_DESC_FONT);
    *nlines = wrap_text(cr, a->description, ANOM_DESC_W, lines, ANOM_DESC_MAX_LINES);
    cairo_restore(cr);

    double row_h = (double)(*nlines > 2 ? *nlines : 2) * ANOM_LINE_H + 10.0;
    return (row_h < 30.0) ? 30.0 : row_h;
}

static int calculate_total_pages(cairo_t *cr, const anomaly_list_t *anomalies)
{
    if (!anomalies || anomalies->count == 0) {
        return 4;
    }

    int anomaly_pages = 1;
    double cur_y = ANOM_FIRST_TABLE_Y + ANOM_HEADER_H;

    for (size_t i = 0; i < anomalies->count; i++) {
        char desc_lines[ANOM_DESC_MAX_LINES][RPT_LINE_BUF];
        size_t nlines;
        double row_h = anomaly_row_layout(cr, &anomalies->items[i], desc_lines, &nlines);

        if (cur_y + row_h > ANOM_MAX_Y) {
            anomaly_pages++;
            cur_y = ANOM_CONT_TABLE_Y + ANOM_HEADER_H;
        }
        cur_y += row_h;
    }

    return 3 + anomaly_pages;
}

static void draw_anomaly_table_header(cairo_t *cr, double y)
{
    double card_x = REPORT_PAGE_MARGIN;
    double card_w = RPT_CONTENT_W;

    cairo_set_source_rgb(cr, RPT_COLOR_TH_BG_R, RPT_COLOR_TH_BG_G, RPT_COLOR_TH_BG_B);
    cairo_rectangle(cr, card_x, y, card_w, ANOM_HEADER_H);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.5);
    cairo_rectangle(cr, card_x, y, card_w, ANOM_HEADER_H);
    cairo_stroke(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

    show_text_fit(cr, card_x + ANOM_COL_SEV_X, y + 12.5,
                  col_w(ANOM_COL_SEV_X, ANOM_COL_CAT_X), "Severity");
    show_text_fit(cr, card_x + ANOM_COL_CAT_X, y + 12.5,
                  col_w(ANOM_COL_CAT_X, ANOM_COL_DESC_X), "Category & Subject");
    show_text_fit(cr, card_x + ANOM_COL_DESC_X, y + 12.5, ANOM_DESC_W,
                  "Finding Details & Metric Analysis");
}

static void render_page4_anomalies(cairo_t *cr,
                                   const anomaly_list_t *anomalies,
                                   int start_page,
                                   int total_pages,
                                   const char *ts_str)
{
    int current_page = start_page;
    double card_x = REPORT_PAGE_MARGIN;
    double card_w = RPT_CONTENT_W;

    /* Header for first anomaly page */
    draw_page_header(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 18.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    show_text_fit(cr, REPORT_PAGE_MARGIN, 68.0, RPT_CONTENT_W, "Detected Network Anomalies");

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    if (!anomalies || anomalies->count == 0) {
        show_text_fit(cr, REPORT_PAGE_MARGIN, 82.0, RPT_CONTENT_W,
                      "Rule-based heuristic evaluation findings and baseline compliance");

        /* Clean "No Anomalies" card */
        double box_y = 110.0;
        double box_h = 70.0;
        double inner_w = card_w - 32.0;
        draw_rounded_rect(cr, card_x, box_y, card_w, box_h, 4.0);
        cairo_set_source_rgb(cr, 0.94, 0.99, 0.95);
        cairo_fill_preserve(cr);
        cairo_set_source_rgb(cr, 0.52, 0.94, 0.67);
        cairo_set_line_width(cr, 0.75);
        cairo_stroke(cr);

        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 12.0);
        cairo_set_source_rgb(cr, RPT_COLOR_OK_R, RPT_COLOR_OK_G, RPT_COLOR_OK_B);
        show_text_fit(cr, card_x + 16.0, box_y + 26.0, inner_w, "No Network Anomalies Detected");

        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 9.0);
        cairo_set_source_rgb(cr, 0.08, 0.40, 0.20);
        char ok_lines[2][RPT_LINE_BUF];
        size_t ok_n = wrap_text(cr,
                                "All analyzed traffic patterns, TCP flags, port distributions, "
                                "and flow behaviors conform to configured baseline thresholds.",
                                inner_w, ok_lines, 2);
        for (size_t j = 0; j < ok_n; j++) {
            cairo_move_to(cr, card_x + 16.0, box_y + 44.0 + 12.0 * (double)j);
            cairo_show_text(cr, ok_lines[j]);
        }

        draw_page_footer(cr, current_page, total_pages, ts_str);
        cairo_show_page(cr);
        return;
    }

    char subhead[128];
    snprintf(subhead, sizeof(subhead),
             "%zu anomaly findings detected and ordered by severity descending",
             anomalies->count);
    show_text_fit(cr, REPORT_PAGE_MARGIN, 82.0, RPT_CONTENT_W, subhead);

    double cur_y = ANOM_FIRST_TABLE_Y;
    draw_anomaly_table_header(cr, cur_y);
    cur_y += ANOM_HEADER_H;

    for (size_t i = 0; i < anomalies->count; i++) {
        const anomaly_t *a = &anomalies->items[i];

        char desc_lines[ANOM_DESC_MAX_LINES][RPT_LINE_BUF];
        size_t nlines;
        double row_h = anomaly_row_layout(cr, a, desc_lines, &nlines);

        /* Check for page overflow */
        if (cur_y + row_h > ANOM_MAX_Y) {
            draw_page_footer(cr, current_page, total_pages, ts_str);
            cairo_show_page(cr);
            current_page++;

            draw_page_header(cr);
            cur_y = ANOM_CONT_TABLE_Y;
            draw_anomaly_table_header(cr, cur_y);
            cur_y += ANOM_HEADER_H;
        }

        /* Zebra background */
        if (i % 2 == 1) {
            cairo_set_source_rgb(cr, RPT_COLOR_ZEBRA_R, RPT_COLOR_ZEBRA_G, RPT_COLOR_ZEBRA_B);
            cairo_rectangle(cr, card_x, cur_y, card_w, row_h);
            cairo_fill(cr);
        }

        /* Row bottom divider */
        cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
        cairo_set_line_width(cr, 0.5);
        cairo_move_to(cr, card_x, cur_y + row_h);
        cairo_line_to(cr, card_x + card_w, cur_y + row_h);
        cairo_stroke(cr);

        /* Severity Badge */
        double badge_w = 64.0;
        double badge_h = 16.0;
        double badge_x = card_x + ANOM_COL_SEV_X;
        double badge_y = cur_y + (row_h - badge_h) / 2.0;

        draw_rounded_rect(cr, badge_x, badge_y, badge_w, badge_h, 3.0);
        if (a->severity == ANOMALY_CRITICAL) {
            cairo_set_source_rgb(cr, RPT_COLOR_CRIT_R, RPT_COLOR_CRIT_G, RPT_COLOR_CRIT_B);
        } else if (a->severity == ANOMALY_WARNING) {
            cairo_set_source_rgb(cr, RPT_COLOR_WARN_R, RPT_COLOR_WARN_G, RPT_COLOR_WARN_B);
        } else {
            cairo_set_source_rgb(cr, RPT_COLOR_INFO_R, RPT_COLOR_INFO_G, RPT_COLOR_INFO_B);
        }
        cairo_fill(cr);

        const char *sev_text = anomaly_severity_str(a->severity);
        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 7.5);
        cairo_set_source_rgb(cr, RPT_COLOR_WHITE_R, RPT_COLOR_WHITE_G, RPT_COLOR_WHITE_B);
        char sev_fit[RPT_TEXT_BUF];
        fit_text(cr, sev_text, badge_w - 8.0, sev_fit, sizeof(sev_fit));
        cairo_text_extents_t sext;
        cairo_text_extents(cr, sev_fit, &sext);
        cairo_move_to(cr, badge_x + (badge_w - sext.width) / 2.0 - sext.x_bearing, badge_y + 11.5);
        cairo_show_text(cr, sev_fit);

        /* Category & Subject (single line each, truncated to column) */
        double cat_w = col_w(ANOM_COL_CAT_X, ANOM_COL_DESC_X);
        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 8.5);
        cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
        show_text_fit(cr, card_x + ANOM_COL_CAT_X, cur_y + 12.0, cat_w, a->category);

        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 7.5);
        cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
        show_text_fit(cr, card_x + ANOM_COL_CAT_X, cur_y + 23.0, cat_w, a->subject);

        /* Description Lines (same font as measured in anomaly_row_layout) */
        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, ANOM_DESC_FONT);
        cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

        double line_y = cur_y + 11.0;
        for (size_t j = 0; j < nlines; j++) {
            cairo_move_to(cr, card_x + ANOM_COL_DESC_X, line_y);
            cairo_show_text(cr, desc_lines[j]);
            line_y += ANOM_LINE_H;
        }

        cur_y += row_h;
    }

    draw_page_footer(cr, current_page, total_pages, ts_str);
    cairo_show_page(cr);
}

/* -------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------- */

int report_generate(const cli_config_t *cfg,
                    const stats_ctx_t *stats,
                    const anomaly_list_t *anomalies,
                    const char *pdf_path)
{
    if (!cfg || !stats || !anomalies || !pdf_path || pdf_path[0] == '\0') {
        return PCAPSTAT_ERR_ARGS;
    }

    cairo_surface_t *surf = cairo_pdf_surface_create(pdf_path, REPORT_PAGE_WIDTH, REPORT_PAGE_HEIGHT);
    if (!surf || cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        if (surf) {
            cairo_surface_destroy(surf);
        }
        return PCAPSTAT_ERR_IO;
    }

    cairo_t *cr = cairo_create(surf);
    if (!cr || cairo_status(cr) != CAIRO_STATUS_SUCCESS) {
        if (cr) {
            cairo_destroy(cr);
        }
        cairo_surface_destroy(surf);
        return PCAPSTAT_ERR_NOMEM;
    }

    /* Format generation timestamp */
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char ts_str[64];
    strftime(ts_str, sizeof(ts_str), "Generated: %Y-%m-%d %H:%M:%S", &tm_info);

    /* Pre-calculate total pages */
    int total_pages = calculate_total_pages(cr, anomalies);

    int rc = PCAPSTAT_OK;

    /* ---------------------------------------------------------------
     * Page 1: Executive Summary
     * --------------------------------------------------------------- */
    draw_page_header(cr);
    render_page1_executive_summary(cr, cfg, stats, anomalies);
    draw_page_footer(cr, 1, total_pages, ts_str);
    cairo_show_page(cr);

    /* ---------------------------------------------------------------
     * Page 2: Traffic Characteristics
     * --------------------------------------------------------------- */
    draw_page_header(cr);
    render_page2_traffic_characteristics(cr, stats);
    draw_page_footer(cr, 2, total_pages, ts_str);
    cairo_show_page(cr);

    /* ---------------------------------------------------------------
     * Page 3: Visualizations (2x2 Vector Charts)
     * --------------------------------------------------------------- */
    draw_page_header(cr);
    rc = render_page3_visualizations(cr, stats);
    if (rc != PCAPSTAT_OK) {
        goto cleanup;
    }
    draw_page_footer(cr, 3, total_pages, ts_str);
    cairo_show_page(cr);

    /* ---------------------------------------------------------------
     * Page 4+: Detected Anomalies
     * --------------------------------------------------------------- */
    render_page4_anomalies(cr, anomalies, 4, total_pages, ts_str);

cleanup:
    {
        cairo_status_t cr_status = cairo_status(cr);
        cairo_destroy(cr);
        cairo_surface_finish(surf);
        cairo_status_t surf_status = cairo_surface_status(surf);
        cairo_surface_destroy(surf);

        if (rc != PCAPSTAT_OK) {
            return rc;
        }
        if (cr_status != CAIRO_STATUS_SUCCESS || surf_status != CAIRO_STATUS_SUCCESS) {
            return PCAPSTAT_ERR_RENDER;
        }
    }

    return PCAPSTAT_OK;
}
