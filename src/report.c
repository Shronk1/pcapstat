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
#include <math.h>
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
        snprintf(buf, sz, "%lu B", (unsigned long)bytes);
    }
}

static void format_count_commas(uint64_t val, char *buf, size_t sz)
{
    char raw[32];
    snprintf(raw, sizeof(raw), "%lu", (unsigned long)val);
    size_t len = strlen(raw);
    size_t commas = (len > 0) ? (len - 1) / 3 : 0;
    if (len + commas >= sz) {
        snprintf(buf, sz, "%lu", (unsigned long)val);
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

static void draw_rounded_rect(cairo_t *cr, double x, double y, double w, double h, double r)
{
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -M_PI / 2.0, 0.0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0.0, M_PI / 2.0);
    cairo_arc(cr, x + r, y + h - r, r, M_PI / 2.0, M_PI);
    cairo_arc(cr, x + r, y + r, r, M_PI, 3.0 * M_PI / 2.0);
    cairo_close_path(cr);
}

/**
 * @brief Wrap long text into an array of lines based on Cairo text extents.
 */
static size_t wrap_text(cairo_t *cr, const char *text, double max_width,
                        char lines[][256], size_t max_lines)
{
    if (!cr || !text || max_width <= 0.0 || max_lines == 0) {
        return 0;
    }

    size_t line_count = 0;
    char current[256];
    current[0] = '\0';
    size_t cur_len = 0;
    const char *p = text;

    while (*p && line_count < max_lines) {
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (!*p) {
            break;
        }

        if (*p == '\n') {
            if (line_count < max_lines) {
                memcpy(lines[line_count], current, cur_len + 1);
                line_count++;
                current[0] = '\0';
                cur_len = 0;
            }
            p++;
            continue;
        }

        char word[128];
        size_t wlen = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && wlen < sizeof(word) - 1) {
            word[wlen++] = *p++;
        }
        word[wlen] = '\0';

        char candidate[256];
        size_t cand_len = 0;
        if (cur_len == 0) {
            cand_len = wlen;
            memcpy(candidate, word, wlen + 1);
        } else if (cur_len + 1 + wlen < sizeof(candidate)) {
            memcpy(candidate, current, cur_len);
            candidate[cur_len] = ' ';
            memcpy(candidate + cur_len + 1, word, wlen + 1);
            cand_len = cur_len + 1 + wlen;
        } else {
            /* Current line full, commit and start new line with word */
            if (line_count < max_lines) {
                memcpy(lines[line_count], current, cur_len + 1);
                line_count++;
            }
            memcpy(current, word, wlen + 1);
            cur_len = wlen;
            continue;
        }

        cairo_text_extents_t ext;
        cairo_text_extents(cr, candidate, &ext);

        if (ext.width <= max_width || cur_len == 0) {
            memcpy(current, candidate, cand_len + 1);
            cur_len = cand_len;
        } else {
            if (line_count < max_lines) {
                memcpy(lines[line_count], current, cur_len + 1);
                line_count++;
            }
            memcpy(current, word, wlen + 1);
            cur_len = wlen;
        }
    }

    if (cur_len > 0 && line_count < max_lines) {
        memcpy(lines[line_count], current, cur_len + 1);
        line_count++;
    }

    return line_count;
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
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 36.0);
    cairo_show_text(cr, "pcapstat — Network Traffic Analysis Report");

    char ver_buf[64];
    snprintf(ver_buf, sizeof(ver_buf), "Version %s", PCAPSTAT_VERSION);
    cairo_text_extents_t ext;
    cairo_text_extents(cr, ver_buf, &ext);
    cairo_move_to(cr, REPORT_PAGE_WIDTH - REPORT_PAGE_MARGIN - ext.width, 36.0);
    cairo_show_text(cr, ver_buf);

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
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 816.0);
    cairo_show_text(cr, timestamp_str);

    char page_buf[64];
    snprintf(page_buf, sizeof(page_buf), "Page %d of %d", page_num, total_pages);
    cairo_text_extents_t ext;
    cairo_text_extents(cr, page_buf, &ext);
    cairo_move_to(cr, REPORT_PAGE_WIDTH - REPORT_PAGE_MARGIN - ext.width, 816.0);
    cairo_show_text(cr, page_buf);
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
    cairo_move_to(cr, x + 10.0, y + 16.0);
    cairo_show_text(cr, title);

    /* Primary Value */
    cairo_set_font_size(cr, 14.5);
    cairo_set_source_rgb(cr, val_r, val_g, val_b);
    cairo_move_to(cr, x + 10.0, y + 38.0);
    cairo_show_text(cr, val);

    /* Subtext */
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 8.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    cairo_move_to(cr, x + 10.0, y + 54.0);
    cairo_show_text(cr, subtext);

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
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 68.0);
    cairo_show_text(cr, "Executive Summary & Traffic Telemetry");

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 82.0);
    cairo_show_text(cr, "Automated network traffic inspection, protocol metrics, and baseline security assessment");

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
    cairo_move_to(cr, card_x + 12.0, card_y + 18.0);
    cairo_show_text(cr, "Capture Sources:");

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
        snprintf(files_summary, sizeof(files_summary), "demo.pcap");
    }

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 8.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    cairo_move_to(cr, card_x + 110.0, card_y + 18.0);
    cairo_show_text(cr, files_summary);

    /* Second line inside capture box */
    char meta_line[256];
    char pkts_str[32];
    format_count_commas(stats->total_packets, pkts_str, sizeof(pkts_str));
    snprintf(meta_line, sizeof(meta_line),
             "Files Processed: %lu  |  Packets: %s  |  Duration: %.2f s  |  Active Flows: %zu  |  Unique Hosts: %zu",
             (unsigned long)stats->files_processed, pkts_str, stats->duration_sec,
             stats->flows_ht ? stats->flows_ht->count : 0,
             stats->hosts_ht ? stats->hosts_ht->count : 0);
    cairo_move_to(cr, card_x + 12.0, card_y + 36.0);
    cairo_show_text(cr, meta_line);

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

    /* Card 2: Capture Duration & Rates */
    char dur_buf[32];
    snprintf(dur_buf, sizeof(dur_buf), "%.2f s", stats->duration_sec);
    char rate_sub[64];
    if (stats->avg_bps >= 1e6) {
        snprintf(rate_sub, sizeof(rate_sub), "%.1f pps | %.2f Mbps", stats->avg_pps, stats->avg_bps / 1e6);
    } else {
        snprintf(rate_sub, sizeof(rate_sub), "%.1f pps | %.1f Kbps", stats->avg_pps, stats->avg_bps / 1e3);
    }
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
    snprintf(proto_sub, sizeof(proto_sub), "Other: %lu | Malformed: %lu",
             (unsigned long)stats->other_packets, (unsigned long)stats->malformed_packets);
    render_kpi_card(cr, card_x, row2_y, kpi_w, kpi_h,
                    "TRANSPORT PROTOCOL SHARE", proto_val, proto_sub,
                    RPT_COLOR_PRIMARY_R, RPT_COLOR_PRIMARY_G, RPT_COLOR_PRIMARY_B);

    /* Card 5: Endpoints & Flows */
    char sess_val[32];
    snprintf(sess_val, sizeof(sess_val), "%zu Flows", stats->flows_ht ? stats->flows_ht->count : 0);
    char sess_sub[64];
    snprintf(sess_sub, sizeof(sess_sub), "%zu unique endpoints active", stats->hosts_ht ? stats->hosts_ht->count : 0);
    render_kpi_card(cr, card_x + kpi_w + 12.0, row2_y, kpi_w, kpi_h,
                    "NETWORK SESSIONS", sess_val, sess_sub,
                    RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

    /* Card 6: TCP Health */
    char tcp_val[32];
    const flow_stats_t *top_f[128];
    size_t tf_count = stats_top_flows(stats, top_f, 128);
    uint64_t total_retrans = 0;
    for (size_t i = 0; i < tf_count; i++) {
        total_retrans += top_f[i]->retransmissions;
    }
    snprintf(tcp_val, sizeof(tcp_val), "%lu Retrans", (unsigned long)total_retrans);
    char tcp_sub[64];
    snprintf(tcp_sub, sizeof(tcp_sub), "SYN: %lu | ACK: %lu | RST: %lu",
             (unsigned long)stats->syn, (unsigned long)stats->ack, (unsigned long)stats->rst);
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
    cairo_move_to(cr, card_x, tbl_y);
    cairo_show_text(cr, "Global Protocol & Wire Volume Breakdown");

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
    cairo_move_to(cr, card_x + 8.0, tbl_y + 12.5);
    cairo_show_text(cr, "Traffic Category");
    cairo_move_to(cr, card_x + 160.0, tbl_y + 12.5);
    cairo_show_text(cr, "Packets");
    cairo_move_to(cr, card_x + 245.0, tbl_y + 12.5);
    cairo_show_text(cr, "Packet Share");
    cairo_move_to(cr, card_x + 335.0, tbl_y + 12.5);
    cairo_show_text(cr, "Volume (Bytes)");
    cairo_move_to(cr, card_x + 440.0, tbl_y + 12.5);
    cairo_show_text(cr, "Volume Share");

    struct {
        const char *label;
        uint64_t pkts;
        uint64_t bytes;
    } proto_rows[5] = {
        {"TCP Traffic", stats->tcp_packets, stats->tcp_bytes},
        {"UDP Traffic", stats->udp_packets, stats->udp_bytes},
        {"Other Well-formed IP", stats->other_packets, 0},
        {"Malformed / Non-IP Frames", stats->malformed_packets, 0},
        {"Total Traffic", stats->total_packets, stats->total_bytes}
    };

    double cur_y = tbl_y + 18.0;
    for (int i = 0; i < 5; i++) {
        if (i % 2 == 1 && i != 4) {
            cairo_set_source_rgb(cr, RPT_COLOR_ZEBRA_R, RPT_COLOR_ZEBRA_G, RPT_COLOR_ZEBRA_B);
            cairo_rectangle(cr, card_x, cur_y, card_w, 16.0);
            cairo_fill(cr);
        } else if (i == 4) {
            cairo_set_source_rgb(cr, RPT_COLOR_TH_BG_R, RPT_COLOR_TH_BG_G, RPT_COLOR_TH_BG_B);
            cairo_rectangle(cr, card_x, cur_y, card_w, 17.0);
            cairo_fill(cr);
        }

        cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
        cairo_set_line_width(cr, 0.5);
        cairo_move_to(cr, card_x, cur_y + 16.0);
        cairo_line_to(cr, card_x + card_w, cur_y + 16.0);
        cairo_stroke(cr);

        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, (i == 4) ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 8.5);
        cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

        cairo_move_to(cr, card_x + 8.0, cur_y + 11.5);
        cairo_show_text(cr, proto_rows[i].label);

        char p_str[32], b_str[32], ps_str[32], bs_str[32];
        format_count_commas(proto_rows[i].pkts, p_str, sizeof(p_str));
        double p_share = stats->total_packets ? (100.0 * (double)proto_rows[i].pkts / (double)stats->total_packets) : 0.0;
        snprintf(ps_str, sizeof(ps_str), "%.1f %%", p_share);

        if (proto_rows[i].bytes > 0 || i < 2 || i == 4) {
            format_bytes(proto_rows[i].bytes, b_str, sizeof(b_str));
            double b_share = stats->total_bytes ? (100.0 * (double)proto_rows[i].bytes / (double)stats->total_bytes) : 0.0;
            snprintf(bs_str, sizeof(bs_str), "%.1f %%", b_share);
        } else {
            snprintf(b_str, sizeof(b_str), "N/A");
            snprintf(bs_str, sizeof(bs_str), "N/A");
        }

        cairo_move_to(cr, card_x + 160.0, cur_y + 11.5);
        cairo_show_text(cr, p_str);
        cairo_move_to(cr, card_x + 245.0, cur_y + 11.5);
        cairo_show_text(cr, ps_str);
        cairo_move_to(cr, card_x + 335.0, cur_y + 11.5);
        cairo_show_text(cr, b_str);
        cairo_move_to(cr, card_x + 440.0, cur_y + 11.5);
        cairo_show_text(cr, bs_str);

        cur_y += (i == 4) ? 17.0 : 16.0;
    }

    /* ---------------------------------------------------------------
     * TCP Flags Table
     * --------------------------------------------------------------- */
    double flag_y = cur_y + 20.0;
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 11.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    cairo_move_to(cr, card_x, flag_y);
    cairo_show_text(cr, "TCP Flags Telemetry & Connection Behavior");

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
    cairo_move_to(cr, card_x + 8.0, flag_y + 12.5);
    cairo_show_text(cr, "TCP Flag / Condition");
    cairo_move_to(cr, card_x + 160.0, flag_y + 12.5);
    cairo_show_text(cr, "Occurrences");
    cairo_move_to(cr, card_x + 245.0, flag_y + 12.5);
    cairo_show_text(cr, "% of TCP Traffic");
    cairo_move_to(cr, card_x + 335.0, flag_y + 12.5);
    cairo_show_text(cr, "Health & Diagnostic Signal");

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

        cairo_move_to(cr, card_x + 8.0, cur_y + 11.0);
        cairo_show_text(cr, flags[i].flag);

        char c_str[32], s_str[32];
        format_count_commas(flags[i].count, c_str, sizeof(c_str));
        double tcp_share = stats->tcp_packets ? (100.0 * (double)flags[i].count / (double)stats->tcp_packets) : 0.0;
        snprintf(s_str, sizeof(s_str), "%.1f %%", tcp_share);

        cairo_move_to(cr, card_x + 160.0, cur_y + 11.0);
        cairo_show_text(cr, c_str);
        cairo_move_to(cr, card_x + 245.0, cur_y + 11.0);
        cairo_show_text(cr, s_str);

        if (i == 7 && flags[i].count > 0) {
            cairo_set_source_rgb(cr, RPT_COLOR_CRIT_R, RPT_COLOR_CRIT_G, RPT_COLOR_CRIT_B);
        } else if (i == 4 && tcp_share > 10.0 && stats->tcp_packets >= 30) {
            cairo_set_source_rgb(cr, RPT_COLOR_WARN_R, RPT_COLOR_WARN_G, RPT_COLOR_WARN_B);
        } else {
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
        }
        cairo_move_to(cr, card_x + 335.0, cur_y + 11.0);
        cairo_show_text(cr, flags[i].diag);

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
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 68.0);
    cairo_show_text(cr, "Traffic Characteristics & Top Rankings");

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 82.0);
    cairo_show_text(cr, "Detailed top-10 rankings for endpoints, destination services, and active network flows");

    double card_x = REPORT_PAGE_MARGIN;
    double card_w = REPORT_PAGE_WIDTH - 2.0 * REPORT_PAGE_MARGIN;

    /* ---------------------------------------------------------------
     * Table 1: Top 10 IP Talkers (Hosts)
     * --------------------------------------------------------------- */
    double tbl1_y = 96.0;
    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 10.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    cairo_move_to(cr, card_x, tbl1_y);
    cairo_show_text(cr, "1. Top 10 IP Talkers (by Total Wire Volume)");

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

    cairo_move_to(cr, card_x + 6.0, tbl1_y + 11.5);
    cairo_show_text(cr, "#");
    cairo_move_to(cr, card_x + 30.0, tbl1_y + 11.5);
    cairo_show_text(cr, "IP Address");
    cairo_move_to(cr, card_x + 175.0, tbl1_y + 11.5);
    cairo_show_text(cr, "TX Pkts");
    cairo_move_to(cr, card_x + 245.0, tbl1_y + 11.5);
    cairo_show_text(cr, "TX Volume");
    cairo_move_to(cr, card_x + 325.0, tbl1_y + 11.5);
    cairo_show_text(cr, "RX Pkts");
    cairo_move_to(cr, card_x + 395.0, tbl1_y + 11.5);
    cairo_show_text(cr, "RX Volume");
    cairo_move_to(cr, card_x + 465.0, tbl1_y + 11.5);
    cairo_show_text(cr, "Total Wire Vol");

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

            cairo_move_to(cr, card_x + 6.0, cur_y + 10.5);
            cairo_show_text(cr, rank_str);
            cairo_move_to(cr, card_x + 30.0, cur_y + 10.5);
            cairo_show_text(cr, ip_str);
            cairo_move_to(cr, card_x + 175.0, cur_y + 10.5);
            cairo_show_text(cr, tx_p);
            cairo_move_to(cr, card_x + 245.0, cur_y + 10.5);
            cairo_show_text(cr, tx_b);
            cairo_move_to(cr, card_x + 325.0, cur_y + 10.5);
            cairo_show_text(cr, rx_p);
            cairo_move_to(cr, card_x + 395.0, cur_y + 10.5);
            cairo_show_text(cr, rx_b);
            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
            cairo_move_to(cr, card_x + 465.0, cur_y + 10.5);
            cairo_show_text(cr, tot_b);
        } else {
            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 7.5);
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
            cairo_move_to(cr, card_x + 30.0, cur_y + 10.5);
            cairo_show_text(cr, "-");
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
    cairo_move_to(cr, card_x, tbl2_y);
    cairo_show_text(cr, "2. Top 10 Destination Ports & Services (by Packet Count)");

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

    cairo_move_to(cr, card_x + 6.0, tbl2_y + 11.5);
    cairo_show_text(cr, "#");
    cairo_move_to(cr, card_x + 30.0, tbl2_y + 11.5);
    cairo_show_text(cr, "Proto");
    cairo_move_to(cr, card_x + 75.0, tbl2_y + 11.5);
    cairo_show_text(cr, "Port");
    cairo_move_to(cr, card_x + 130.0, tbl2_y + 11.5);
    cairo_show_text(cr, "Service Name");
    cairo_move_to(cr, card_x + 245.0, tbl2_y + 11.5);
    cairo_show_text(cr, "Packets");
    cairo_move_to(cr, card_x + 345.0, tbl2_y + 11.5);
    cairo_show_text(cr, "Wire Volume");
    cairo_move_to(cr, card_x + 445.0, tbl2_y + 11.5);
    cairo_show_text(cr, "% of Total Packets");

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

            cairo_move_to(cr, card_x + 6.0, cur_y + 10.5);
            cairo_show_text(cr, rank_str);
            cairo_move_to(cr, card_x + 30.0, cur_y + 10.5);
            cairo_show_text(cr, proto_name);
            cairo_move_to(cr, card_x + 75.0, cur_y + 10.5);
            cairo_show_text(cr, port_str);
            cairo_move_to(cr, card_x + 130.0, cur_y + 10.5);
            cairo_show_text(cr, svc_name);
            cairo_move_to(cr, card_x + 245.0, cur_y + 10.5);
            cairo_show_text(cr, p_str);
            cairo_move_to(cr, card_x + 345.0, cur_y + 10.5);
            cairo_show_text(cr, b_str);
            cairo_move_to(cr, card_x + 445.0, cur_y + 10.5);
            cairo_show_text(cr, share_str);
        } else {
            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 7.5);
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
            cairo_move_to(cr, card_x + 30.0, cur_y + 10.5);
            cairo_show_text(cr, "-");
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
    cairo_move_to(cr, card_x, tbl3_y);
    cairo_show_text(cr, "3. Top 10 Directional 5-Tuple Network Flows");

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

    cairo_move_to(cr, card_x + 6.0, tbl3_y + 11.5);
    cairo_show_text(cr, "#");
    cairo_move_to(cr, card_x + 26.0, tbl3_y + 11.5);
    cairo_show_text(cr, "Proto");
    cairo_move_to(cr, card_x + 62.0, tbl3_y + 11.5);
    cairo_show_text(cr, "Flow 5-Tuple (Source:Port -> Destination:Port)");
    cairo_move_to(cr, card_x + 305.0, tbl3_y + 11.5);
    cairo_show_text(cr, "Packets");
    cairo_move_to(cr, card_x + 365.0, tbl3_y + 11.5);
    cairo_show_text(cr, "Volume");
    cairo_move_to(cr, card_x + 425.0, tbl3_y + 11.5);
    cairo_show_text(cr, "Retrans");
    cairo_move_to(cr, card_x + 475.0, tbl3_y + 11.5);
    cairo_show_text(cr, "Duration");

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
            snprintf(r_str, sizeof(r_str), "%lu", (unsigned long)f->retransmissions);

            if (f->has_timestamp && f->last_ts >= f->first_ts) {
                snprintf(dur_str, sizeof(dur_str), "%.2f s", f->last_ts - f->first_ts);
            } else {
                snprintf(dur_str, sizeof(dur_str), "-");
            }

            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 7.5);
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

            cairo_move_to(cr, card_x + 6.0, cur_y + 10.5);
            cairo_show_text(cr, rank_str);
            cairo_move_to(cr, card_x + 26.0, cur_y + 10.5);
            cairo_show_text(cr, proto_name);
            cairo_move_to(cr, card_x + 62.0, cur_y + 10.5);
            cairo_show_text(cr, tuple_str);
            cairo_move_to(cr, card_x + 305.0, cur_y + 10.5);
            cairo_show_text(cr, p_str);
            cairo_move_to(cr, card_x + 365.0, cur_y + 10.5);
            cairo_show_text(cr, b_str);

            if (f->retransmissions > 0) {
                cairo_set_source_rgb(cr, RPT_COLOR_WARN_R, RPT_COLOR_WARN_G, RPT_COLOR_WARN_B);
            }
            cairo_move_to(cr, card_x + 425.0, cur_y + 10.5);
            cairo_show_text(cr, r_str);

            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
            cairo_move_to(cr, card_x + 475.0, cur_y + 10.5);
            cairo_show_text(cr, dur_str);
        } else {
            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 7.5);
            cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
            cairo_move_to(cr, card_x + 30.0, cur_y + 10.5);
            cairo_show_text(cr, "-");
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
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 68.0);
    cairo_show_text(cr, "Visualizations & Traffic Patterns");

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 82.0);
    cairo_show_text(cr, "Embedded vector charts rendered directly into the PDF coordinate system");

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

static int calculate_total_pages(cairo_t *cr, const anomaly_list_t *anomalies)
{
    if (!anomalies || anomalies->count == 0) {
        return 4;
    }

    int anomaly_pages = 1;
    double cur_y = 114.0;
    const double max_y = 785.0;

    for (size_t i = 0; i < anomalies->count; i++) {
        const anomaly_t *a = &anomalies->items[i];
        char desc_lines[16][256];

        cairo_save(cr);
        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 8.5);
        size_t nlines = wrap_text(cr, a->description, 290.0, desc_lines, 16);
        cairo_restore(cr);

        double row_h = (nlines > 2 ? nlines : 2) * 12.0 + 10.0;
        if (row_h < 30.0) {
            row_h = 30.0;
        }

        if (cur_y + row_h > max_y) {
            anomaly_pages++;
            cur_y = 80.0 + row_h;
        } else {
            cur_y += row_h;
        }
    }

    return 3 + anomaly_pages;
}

static void draw_anomaly_table_header(cairo_t *cr, double y)
{
    double card_x = REPORT_PAGE_MARGIN;
    double card_w = REPORT_PAGE_WIDTH - 2.0 * REPORT_PAGE_MARGIN;

    cairo_set_source_rgb(cr, RPT_COLOR_TH_BG_R, RPT_COLOR_TH_BG_G, RPT_COLOR_TH_BG_B);
    cairo_rectangle(cr, card_x, y, card_w, 18.0);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, RPT_COLOR_BORDER_R, RPT_COLOR_BORDER_G, RPT_COLOR_BORDER_B);
    cairo_set_line_width(cr, 0.5);
    cairo_rectangle(cr, card_x, y, card_w, 18.0);
    cairo_stroke(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.5);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

    cairo_move_to(cr, card_x + 8.0, y + 12.5);
    cairo_show_text(cr, "Severity");
    cairo_move_to(cr, card_x + 85.0, y + 12.5);
    cairo_show_text(cr, "Category & Subject");
    cairo_move_to(cr, card_x + 225.0, y + 12.5);
    cairo_show_text(cr, "Finding Details & Metric Analysis");
}

static void render_page4_anomalies(cairo_t *cr,
                                   const anomaly_list_t *anomalies,
                                   int start_page,
                                   int total_pages,
                                   const char *ts_str)
{
    int current_page = start_page;
    double card_x = REPORT_PAGE_MARGIN;
    double card_w = REPORT_PAGE_WIDTH - 2.0 * REPORT_PAGE_MARGIN;

    /* Header for first anomaly page */
    draw_page_header(cr);

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 18.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 68.0);
    cairo_show_text(cr, "Detected Network Anomalies");

    cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.0);
    cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
    cairo_move_to(cr, REPORT_PAGE_MARGIN, 82.0);

    if (!anomalies || anomalies->count == 0) {
        cairo_show_text(cr, "Rule-based heuristic evaluation findings and baseline compliance");

        /* Clean "No Anomalies" card */
        double box_y = 110.0;
        double box_h = 70.0;
        draw_rounded_rect(cr, card_x, box_y, card_w, box_h, 4.0);
        cairo_set_source_rgb(cr, 0.94, 0.99, 0.95);
        cairo_fill_preserve(cr);
        cairo_set_source_rgb(cr, 0.52, 0.94, 0.67);
        cairo_set_line_width(cr, 0.75);
        cairo_stroke(cr);

        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 12.0);
        cairo_set_source_rgb(cr, RPT_COLOR_OK_R, RPT_COLOR_OK_G, RPT_COLOR_OK_B);
        cairo_move_to(cr, card_x + 16.0, box_y + 26.0);
        cairo_show_text(cr, "No Network Anomalies Detected");

        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 9.0);
        cairo_set_source_rgb(cr, 0.08, 0.40, 0.20);
        cairo_move_to(cr, card_x + 16.0, box_y + 44.0);
        cairo_show_text(cr, "All analyzed traffic patterns, TCP flags, port distributions, and flow behaviors conform to configured baseline thresholds.");

        draw_page_footer(cr, current_page, total_pages, ts_str);
        cairo_show_page(cr);
        return;
    }

    char subhead[128];
    snprintf(subhead, sizeof(subhead),
             "%zu anomaly findings detected and ordered by severity descending",
             anomalies->count);
    cairo_show_text(cr, subhead);

    double cur_y = 96.0;
    draw_anomaly_table_header(cr, cur_y);
    cur_y += 18.0;

    const double max_page_y = 785.0;

    for (size_t i = 0; i < anomalies->count; i++) {
        const anomaly_t *a = &anomalies->items[i];

        /* Word-wrap description */
        char desc_lines[16][256];
        cairo_save(cr);
        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 8.5);
        size_t nlines = wrap_text(cr, a->description, 285.0, desc_lines, 16);
        cairo_restore(cr);

        double row_h = (nlines > 2 ? nlines : 2) * 12.0 + 10.0;
        if (row_h < 30.0) {
            row_h = 30.0;
        }

        /* Check for page overflow */
        if (cur_y + row_h > max_page_y) {
            draw_page_footer(cr, current_page, total_pages, ts_str);
            cairo_show_page(cr);
            current_page++;

            draw_page_header(cr);
            cur_y = 60.0;
            draw_anomaly_table_header(cr, cur_y);
            cur_y += 18.0;
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
        double badge_x = card_x + 8.0;
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
        cairo_text_extents_t sext;
        cairo_text_extents(cr, sev_text, &sext);
        cairo_move_to(cr, badge_x + (badge_w - sext.width) / 2.0, badge_y + 11.5);
        cairo_show_text(cr, sev_text);

        /* Category & Subject */
        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 8.5);
        cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);
        cairo_move_to(cr, card_x + 85.0, cur_y + 12.0);
        cairo_show_text(cr, a->category);

        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 7.5);
        cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MUTED_R, RPT_COLOR_TEXT_MUTED_G, RPT_COLOR_TEXT_MUTED_B);
        cairo_move_to(cr, card_x + 85.0, cur_y + 23.0);
        cairo_show_text(cr, a->subject);

        /* Description Lines */
        cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 8.0);
        cairo_set_source_rgb(cr, RPT_COLOR_TEXT_MAIN_R, RPT_COLOR_TEXT_MAIN_G, RPT_COLOR_TEXT_MAIN_B);

        double line_y = cur_y + 11.0;
        for (size_t j = 0; j < nlines; j++) {
            cairo_move_to(cr, card_x + 225.0, line_y);
            cairo_show_text(cr, desc_lines[j]);
            line_y += 12.0;
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
