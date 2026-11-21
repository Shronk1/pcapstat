/**
 * @file charts.c
 * @brief Implementation of vector chart rendering and PNG exports via libcairo.
 */

#include "charts.h"
#include "common.h"
#include "stats.h"

#include <cairo.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------
 * Color Palette Constants (RGB 0.0 - 1.0)
 * ------------------------------------------------------------------- */

/* Background & Surfaces */
#define COLOR_BG_R          1.0
#define COLOR_BG_G          1.0
#define COLOR_BG_B          1.0

#define COLOR_FRAME_BG_R    0.98
#define COLOR_FRAME_BG_G    0.98
#define COLOR_FRAME_BG_B    0.99

/* Gridlines & Borders */
#define COLOR_GRID_R        0.89
#define COLOR_GRID_G        0.91
#define COLOR_GRID_B        0.94

#define COLOR_AXIS_R        0.60
#define COLOR_AXIS_G        0.65
#define COLOR_AXIS_B        0.72

/* Typography */
#define COLOR_TEXT_TITLE_R  0.12
#define COLOR_TEXT_TITLE_G  0.16
#define COLOR_TEXT_TITLE_B  0.23

#define COLOR_TEXT_LABEL_R  0.39
#define COLOR_TEXT_LABEL_G  0.45
#define COLOR_TEXT_LABEL_B  0.55

#define COLOR_TEXT_MUTED_R  0.60
#define COLOR_TEXT_MUTED_G  0.64
#define COLOR_TEXT_MUTED_B  0.72

/* Series / Accent Colors */
#define COLOR_TCP_R         0.15
#define COLOR_TCP_G         0.39
#define COLOR_TCP_B         0.92

#define COLOR_UDP_R         0.98
#define COLOR_UDP_G         0.45
#define COLOR_UDP_B         0.09

#define COLOR_BAR_BLUE_R    0.23
#define COLOR_BAR_BLUE_G    0.51
#define COLOR_BAR_BLUE_B    0.96

#define COLOR_HIST_R        0.31
#define COLOR_HIST_G        0.27
#define COLOR_HIST_B        0.90

/* Number of bars in the TCP flag chart: 7 flags + "Suspicious". */
#define TCP_FLAG_BARS 8

/* TCP Flag Palette */
static const double TCP_FLAG_COLORS[TCP_FLAG_BARS][3] = {
    {0.15, 0.39, 0.92}, /* SYN: Blue */
    {0.39, 0.40, 0.95}, /* SYN-ACK: Indigo */
    {0.06, 0.73, 0.51}, /* ACK: Emerald */
    {0.96, 0.62, 0.04}, /* FIN: Amber */
    {0.94, 0.27, 0.27}, /* RST: Red */
    {0.55, 0.36, 0.96}, /* PSH: Purple */
    {0.93, 0.28, 0.60}, /* URG: Pink */
    {0.70, 0.05, 0.10}  /* Suspicious: Dark red */
};

/* Largest time offset (seconds) the X-axis formatter prints. Below 2^64,
 * so converting the rounded value to uint64_t is always defined. Bucket
 * seconds lie within about +/-9e18 (see stats.h), so real spans fit. */
#define TIME_LABEL_MAX_SEC 1.8e19

/* -------------------------------------------------------------------
 * Formatting and Drawing Helpers
 * ------------------------------------------------------------------- */

/**
 * @brief Format numeric count with compact metric suffix (e.g. 1.2K, 3.5M).
 */
static void format_metric(char *buf, size_t sz, double val)
{
    if (val < 0.0) {
        val = 0.0;
    }

    if (val >= 1e9) {
        snprintf(buf, sz, "%.1fG", val / 1e9);
    } else if (val >= 1e6) {
        snprintf(buf, sz, "%.1fM", val / 1e6);
    } else if (val >= 1e3) {
        if (val < 10e3) {
            snprintf(buf, sz, "%.1fK", val / 1e3);
        } else {
            snprintf(buf, sz, "%.0fK", val / 1e3);
        }
    } else {
        snprintf(buf, sz, "%.0f", val);
    }
}

/**
 * @brief Format a value-axis tick label.
 *
 * Ticks are axis_max * k / 4 with axis_max in {1, 2, 2.5, 5} * 10^n, so
 * they can be fractional (0.25, 2.5, 12.5, ...); "%.0f" would print the
 * ticks of a 0..1 axis as "0 0 0 1 1" and 2.5 as "2". Below 1000 the
 * value is therefore printed with %g: exact for quarter ticks, integers
 * stay integers (no trailing ".0"), so every axis whose maximum is < 10
 * gets decimals. From 1000 up the compact metric format is kept.
 */
static void format_axis_tick(char *buf, size_t sz, double val)
{
    if (!(val > 0.0)) {
        val = 0.0;
    }
    if (val < 1000.0) {
        snprintf(buf, sz, "%g", val);
    } else {
        format_metric(buf, sz, val);
    }
}

/**
 * @brief Round @p sec to the nearest whole @p unit, clamped to
 *        [0, TIME_LABEL_MAX_SEC / unit] (NaN and negatives give 0).
 */
static uint64_t round_time_units(double sec, double unit)
{
    if (!(sec > 0.0)) {
        return 0;
    }
    double v = floor(sec / unit + 0.5);
    double cap = floor(TIME_LABEL_MAX_SEC / unit);
    if (!(v < cap)) {
        v = cap;
    }
    return (uint64_t)v;
}

/**
 * @brief Format an offset from the start of the capture as an X-axis label.
 *
 * The unit depends on the whole axis span (not on the tick value), so all
 * ticks of one axis share a format:
 *   span < 60 s   "+12s", "+2.5s"  (%g: exact for quarter ticks)
 *   span < 1 h    "+05:30"         (minutes:seconds)
 *   span < 1 d    "+3h05m"
 *   otherwise     "+2d04h"
 * From one minute up, values are rounded to the displayed unit and
 * clamped, so any span that fits in int64_t seconds yields a
 * non-negative, untruncated label.
 */
static void format_time_offset(char *buf, size_t sz, double offset_sec,
                               double span_sec)
{
    if (!(offset_sec > 0.0)) {
        offset_sec = 0.0;
    }

    if (span_sec < 60.0) {
        if (offset_sec > span_sec) {
            offset_sec = span_sec;
        }
        snprintf(buf, sz, "+%gs", offset_sec);
    } else if (span_sec < 3600.0) {
        uint64_t s = round_time_units(offset_sec, 1.0);
        snprintf(buf, sz, "+%02" PRIu64 ":%02u", s / 60, (unsigned)(s % 60));
    } else if (span_sec < 86400.0) {
        uint64_t m = round_time_units(offset_sec, 60.0);
        snprintf(buf, sz, "+%" PRIu64 "h%02um", m / 60, (unsigned)(m % 60));
    } else {
        uint64_t h = round_time_units(offset_sec, 3600.0);
        snprintf(buf, sz, "+%" PRIu64 "d%02uh", h / 24, (unsigned)(h % 24));
    }
}

/**
 * @brief Format a port bar label as "<port>/<proto> (<service>)",
 *        e.g. "53/udp (DNS)".
 *
 * TCP and UDP ports with the same number are separate bars, so the
 * protocol must be part of the label.
 */
static void format_port_label(char *buf, size_t sz, const port_stats_t *p)
{
    const char *svc = stats_port_service_name(p->proto, p->dst_port);

    if (p->proto == IPPROTO_TCP) {
        snprintf(buf, sz, "%u/tcp (%s)", (unsigned)p->dst_port, svc);
    } else if (p->proto == IPPROTO_UDP) {
        snprintf(buf, sz, "%u/udp (%s)", (unsigned)p->dst_port, svc);
    } else {
        snprintf(buf, sz, "%u/%u (%s)", (unsigned)p->dst_port,
                 (unsigned)p->proto, svc);
    }
}

/**
 * @brief Restore the caller's Cairo state and report the context status.
 *
 * @return PCAPSTAT_OK, or PCAPSTAT_ERR_RENDER if the context is in an
 *         error state (an error during drawing, or already on entry).
 */
static int finish_draw(cairo_t *cr)
{
    cairo_restore(cr);
    return (cairo_status(cr) == CAIRO_STATUS_SUCCESS) ? PCAPSTAT_OK
                                                      : PCAPSTAT_ERR_RENDER;
}

/**
 * @brief Round an arbitrary positive value up to a "nice" axis ceiling.
 */
static double calculate_nice_max(double max_val)
{
    if (max_val <= 0.0) {
        return 1.0;
    }

    double exponent = floor(log10(max_val));
    double fraction = max_val / pow(10.0, exponent);
    double nice_fraction;

    if (fraction <= 1.0) {
        nice_fraction = 1.0;
    } else if (fraction <= 2.0) {
        nice_fraction = 2.0;
    } else if (fraction <= 2.5) {
        nice_fraction = 2.5;
    } else if (fraction <= 5.0) {
        nice_fraction = 5.0;
    } else {
        nice_fraction = 10.0;
    }

    return nice_fraction * pow(10.0, exponent);
}

/**
 * @brief Calculate UI scaling factor based on bounding box width.
 */
static double get_ui_scale(double width)
{
    double scale = width / 700.0;
    if (scale < 0.55) {
        scale = 0.55;
    } else if (scale > 1.20) {
        scale = 1.20;
    }
    return scale;
}

/**
 * @brief Render a standard chart title at the top of the bounding box.
 */
static void draw_chart_title(cairo_t *cr, double x, double y, double scale, const char *title)
{
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 14.0 * scale);
    cairo_set_source_rgb(cr, COLOR_TEXT_TITLE_R, COLOR_TEXT_TITLE_G, COLOR_TEXT_TITLE_B);
    cairo_move_to(cr, x + 16.0 * scale, y + 24.0 * scale);
    cairo_show_text(cr, title);
}

/**
 * @brief Render empty-state placeholder when no traffic matches the chart criteria.
 */
static void draw_empty_placeholder(cairo_t *cr, double x, double y,
                                   double w, double h, const char *title,
                                   const char *msg)
{
    double scale = get_ui_scale(w);

    /* Background fill */
    cairo_set_source_rgb(cr, COLOR_BG_R, COLOR_BG_G, COLOR_BG_B);
    cairo_rectangle(cr, x, y, w, h);
    cairo_fill(cr);

    /* Title */
    draw_chart_title(cr, x, y, scale, title);

    /* Plot area frame */
    double frame_x = x + 16.0 * scale;
    double frame_y = y + 42.0 * scale;
    double frame_w = w - 32.0 * scale;
    double frame_h = h - 58.0 * scale;

    if (frame_w > 10.0 && frame_h > 10.0) {
        cairo_set_source_rgb(cr, COLOR_FRAME_BG_R, COLOR_FRAME_BG_G, COLOR_FRAME_BG_B);
        cairo_rectangle(cr, frame_x, frame_y, frame_w, frame_h);
        cairo_fill(cr);

        cairo_set_source_rgb(cr, COLOR_GRID_R, COLOR_GRID_G, COLOR_GRID_B);
        cairo_set_line_width(cr, 1.0);
        cairo_rectangle(cr, frame_x, frame_y, frame_w, frame_h);
        cairo_stroke(cr);

        /* Centered message */
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 12.0 * scale);
        cairo_set_source_rgb(cr, COLOR_TEXT_MUTED_R, COLOR_TEXT_MUTED_G, COLOR_TEXT_MUTED_B);

        cairo_text_extents_t ext;
        cairo_text_extents(cr, msg, &ext);
        double cx = frame_x + frame_w / 2.0;
        double cy = frame_y + frame_h / 2.0;
        cairo_move_to(cr, cx - (ext.width / 2.0 + ext.x_bearing),
                          cy - (ext.height / 2.0 + ext.y_bearing));
        cairo_show_text(cr, msg);
    }
}

/* -------------------------------------------------------------------
 * Timeline Geometry Helpers
 * ------------------------------------------------------------------- */

/** Plot area and axis scales of the traffic timeline. */
typedef struct {
    double  x, y, w, h;  /* plot area */
    int64_t t_start;     /* first second on the X axis */
    double  t_total;     /* seconds covered by the X axis (> 0) */
    double  y_max;       /* packet rate at the top of the Y axis (> 0) */
} timeline_axes_t;

/**
 * @brief Seconds from @p t0 to @p sec (0 if sec <= t0).
 *
 * Bucket seconds may lie anywhere in about +/-9e18, so the signed
 * difference can exceed INT64_MAX; the unsigned difference is exact.
 */
static double sec_offset(int64_t sec, int64_t t0)
{
    if (sec <= t0) {
        return 0.0;
    }
    return (double)((uint64_t)sec - (uint64_t)t0);
}

/** Seconds covered by a bucket (span_sec, at least 1). */
static uint64_t bucket_span(const ts_bucket_t *b)
{
    return (b->span_sec > 0) ? b->span_sec : 1;
}

/** True if @p cur does not start where @p prev ends (no traffic between). */
static bool bucket_gap_before(const ts_bucket_t *prev, const ts_bucket_t *cur)
{
    if (cur->sec <= prev->sec) {
        return false;
    }
    return (uint64_t)cur->sec - (uint64_t)prev->sec > bucket_span(prev);
}

/** Map a capture-relative time to an X coordinate inside the plot. */
static double timeline_px(const timeline_axes_t *ax, double t)
{
    double px = ax->x + (t / ax->t_total) * ax->w;
    if (px < ax->x) px = ax->x;
    if (px > ax->x + ax->w) px = ax->x + ax->w;
    return px;
}

/** Map a packet rate to a Y coordinate inside the plot. */
static double timeline_py(const timeline_axes_t *ax, double rate)
{
    double py = ax->y + ax->h - (rate / ax->y_max) * ax->h;
    if (py < ax->y) py = ax->y;
    if (py > ax->y + ax->h) py = ax->y + ax->h;
    return py;
}

/**
 * @brief Stroke the TCP or UDP packet-rate series of the timeline.
 *
 * Consecutive buckets are joined at their midpoints. Across a gap between
 * buckets (no packets seen) the line drops to 0 at the end of the previous
 * bucket and rises from 0 at the start of the next one, instead of
 * interpolating a rate that never existed. A lone bucket (a single point)
 * is drawn as a flat segment over its span so it stays visible.
 */
static void stroke_rate_series(cairo_t *cr, const stats_ctx_t *stats,
                               const timeline_axes_t *ax, bool udp)
{
    double base_y = ax->y + ax->h;

    if (stats->timeline_count == 1) {
        const ts_bucket_t *b = &stats->timeline[0];
        double span = (double)bucket_span(b);
        double pkts = (double)(udp ? b->udp_packets : b->tcp_packets);
        double py = timeline_py(ax, pkts / span);
        cairo_move_to(cr, timeline_px(ax, 0.0), py);
        cairo_line_to(cr, timeline_px(ax, span), py);
        cairo_stroke(cr);
        return;
    }

    for (size_t i = 0; i < stats->timeline_count; i++) {
        const ts_bucket_t *b = &stats->timeline[i];
        double span = (double)bucket_span(b);
        double pkts = (double)(udp ? b->udp_packets : b->tcp_packets);
        double t0 = sec_offset(b->sec, ax->t_start);
        double px = timeline_px(ax, t0 + span / 2.0);
        double py = timeline_py(ax, pkts / span);

        if (i == 0) {
            cairo_move_to(cr, px, py);
            continue;
        }

        const ts_bucket_t *prev = &stats->timeline[i - 1];
        if (bucket_gap_before(prev, b)) {
            double prev_end = sec_offset(prev->sec, ax->t_start) +
                              (double)bucket_span(prev);
            cairo_line_to(cr, timeline_px(ax, prev_end), base_y);
            cairo_line_to(cr, timeline_px(ax, t0), base_y);
        }
        cairo_line_to(cr, px, py);
    }
    cairo_stroke(cr);
}

/* -------------------------------------------------------------------
 * Reusable Vector Drawing Implementations
 * ------------------------------------------------------------------- */

int chart_draw_traffic_timeline(cairo_t *cr, const stats_ctx_t *stats,
                                double x, double y, double width, double height)
{
    if (!cr || !stats || width <= 0.0 || height <= 0.0) {
        return PCAPSTAT_ERR_ARGS;
    }

    cairo_save(cr);
    cairo_rectangle(cr, x, y, width, height);
    cairo_clip(cr);

    const char *title_text = "Traffic Timeline (Packets/s)";

    /* Handle empty dataset */
    if (stats->timeline_count == 0 || !stats->timeline) {
        draw_empty_placeholder(cr, x, y, width, height, title_text,
                               "No timeline data available");
        return finish_draw(cr);
    }

    /* Fill background */
    cairo_set_source_rgb(cr, COLOR_BG_R, COLOR_BG_G, COLOR_BG_B);
    cairo_rectangle(cr, x, y, width, height);
    cairo_fill(cr);

    double scale = get_ui_scale(width);
    draw_chart_title(cr, x, y, scale, title_text);

    /* Plot area dimensions */
    double margin_left = 60.0 * scale;
    double margin_right = 24.0 * scale;
    double margin_top = 50.0 * scale;
    double margin_bottom = 36.0 * scale;

    double plot_x = x + margin_left;
    double plot_y = y + margin_top;
    double plot_w = width - margin_left - margin_right;
    double plot_h = height - margin_top - margin_bottom;

    if (plot_w <= 20.0 || plot_h <= 20.0) {
        cairo_restore(cr);
        return PCAPSTAT_ERR_ARGS;
    }

    /* Determine maximum packet rates */
    double max_rate = 0.0;
    for (size_t i = 0; i < stats->timeline_count; i++) {
        const ts_bucket_t *b = &stats->timeline[i];
        double span = (double)bucket_span(b);
        double tcp_r = (double)b->tcp_packets / span;
        double udp_r = (double)b->udp_packets / span;
        if (tcp_r > max_rate) {
            max_rate = tcp_r;
        }
        if (udp_r > max_rate) {
            max_rate = udp_r;
        }
    }

    if (max_rate <= 0.0) {
        max_rate = 1.0;
    }
    double nice_max = calculate_nice_max(max_rate);

    /* Draw plot area background */
    cairo_set_source_rgb(cr, COLOR_FRAME_BG_R, COLOR_FRAME_BG_G, COLOR_FRAME_BG_B);
    cairo_rectangle(cr, plot_x, plot_y, plot_w, plot_h);
    cairo_fill(cr);

    /* Draw horizontal gridlines and Y-axis labels */
    int num_y_ticks = 4;
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.0 * scale);

    for (int i = 0; i <= num_y_ticks; i++) {
        double tick_val = nice_max * ((double)i / (double)num_y_ticks);
        double grid_y = plot_y + plot_h - (plot_h * ((double)i / (double)num_y_ticks));

        /* Gridline */
        cairo_set_source_rgb(cr, COLOR_GRID_R, COLOR_GRID_G, COLOR_GRID_B);
        cairo_set_line_width(cr, (i == 0) ? 1.5 : 1.0);
        cairo_move_to(cr, plot_x, grid_y);
        cairo_line_to(cr, plot_x + plot_w, grid_y);
        cairo_stroke(cr);

        /* Y-tick label */
        char lbl[32];
        format_axis_tick(lbl, sizeof(lbl), tick_val);
        cairo_text_extents_t ext;
        cairo_text_extents(cr, lbl, &ext);
        cairo_set_source_rgb(cr, COLOR_TEXT_LABEL_R, COLOR_TEXT_LABEL_G, COLOR_TEXT_LABEL_B);
        cairo_move_to(cr, plot_x - ext.x_advance - 6.0 * scale,
                          grid_y - (ext.height / 2.0 + ext.y_bearing));
        cairo_show_text(cr, lbl);
    }

    /* Time range for X-axis: from the first bucket's start to the last
     * bucket's end, computed without signed overflow (see sec_offset). */
    const ts_bucket_t *first = &stats->timeline[0];
    const ts_bucket_t *last = &stats->timeline[stats->timeline_count - 1];
    timeline_axes_t ax = {
        .x = plot_x, .y = plot_y, .w = plot_w, .h = plot_h,
        .t_start = first->sec,
        .t_total = sec_offset(last->sec, first->sec) + (double)bucket_span(last),
        .y_max = nice_max
    };
    if (!(ax.t_total > 0.0)) {
        ax.t_total = 1.0;
    }

    /* Draw X-axis tick labels */
    int num_x_ticks = 4;
    for (int i = 0; i <= num_x_ticks; i++) {
        double frac = (double)i / (double)num_x_ticks;
        double grid_x = plot_x + plot_w * frac;
        double offset_sec = ax.t_total * frac;

        /* Subtle vertical gridline */
        cairo_set_source_rgb(cr, COLOR_GRID_R, COLOR_GRID_G, COLOR_GRID_B);
        cairo_set_line_width(cr, 1.0);
        cairo_move_to(cr, grid_x, plot_y);
        cairo_line_to(cr, grid_x, plot_y + plot_h);
        cairo_stroke(cr);

        /* X-tick label, kept inside the bounding box so the long
         * day-scale labels at the edges are not clipped. */
        char lbl[48];
        format_time_offset(lbl, sizeof(lbl), offset_sec, ax.t_total);

        cairo_text_extents_t ext;
        cairo_text_extents(cr, lbl, &ext);
        double lbl_x = grid_x - (ext.width / 2.0 + ext.x_bearing);
        double lbl_max_x = x + width - 4.0 * scale - (ext.width + ext.x_bearing);
        double lbl_min_x = x + 4.0 * scale - ext.x_bearing;
        if (lbl_x > lbl_max_x) {
            lbl_x = lbl_max_x;
        }
        if (lbl_x < lbl_min_x) {
            lbl_x = lbl_min_x;
        }
        cairo_set_source_rgb(cr, COLOR_TEXT_LABEL_R, COLOR_TEXT_LABEL_G, COLOR_TEXT_LABEL_B);
        cairo_move_to(cr, lbl_x, plot_y + plot_h + 14.0 * scale);
        cairo_show_text(cr, lbl);
    }

    /* Plot area border, drawn before the series: on long captures a
     * one-second bucket at either end is a vertical spike lying exactly
     * on the frame and must not be hidden by it. */
    cairo_set_source_rgb(cr, COLOR_AXIS_R, COLOR_AXIS_G, COLOR_AXIS_B);
    cairo_set_line_width(cr, 1.0);
    cairo_rectangle(cr, plot_x, plot_y, plot_w, plot_h);
    cairo_stroke(cr);

    /* Plot TCP line (Blue) */
    cairo_set_source_rgb(cr, COLOR_TCP_R, COLOR_TCP_G, COLOR_TCP_B);
    cairo_set_line_width(cr, 2.0 * scale);
    stroke_rate_series(cr, stats, &ax, false);

    /* Plot UDP line (Orange) */
    cairo_set_source_rgb(cr, COLOR_UDP_R, COLOR_UDP_G, COLOR_UDP_B);
    cairo_set_line_width(cr, 2.0 * scale);
    stroke_rate_series(cr, stats, &ax, true);

    /* Draw Legend at top right */
    double leg_x = plot_x + plot_w - 130.0 * scale;
    double leg_y = y + 16.0 * scale;

    /* TCP legend item */
    cairo_set_source_rgb(cr, COLOR_TCP_R, COLOR_TCP_G, COLOR_TCP_B);
    cairo_rectangle(cr, leg_x, leg_y, 10.0 * scale, 10.0 * scale);
    cairo_fill(cr);

    cairo_set_font_size(cr, 10.0 * scale);
    cairo_set_source_rgb(cr, COLOR_TEXT_TITLE_R, COLOR_TEXT_TITLE_G, COLOR_TEXT_TITLE_B);
    cairo_move_to(cr, leg_x + 14.0 * scale, leg_y + 9.0 * scale);
    cairo_show_text(cr, "TCP");

    /* UDP legend item */
    double leg2_x = leg_x + 55.0 * scale;
    cairo_set_source_rgb(cr, COLOR_UDP_R, COLOR_UDP_G, COLOR_UDP_B);
    cairo_rectangle(cr, leg2_x, leg_y, 10.0 * scale, 10.0 * scale);
    cairo_fill(cr);

    cairo_set_source_rgb(cr, COLOR_TEXT_TITLE_R, COLOR_TEXT_TITLE_G, COLOR_TEXT_TITLE_B);
    cairo_move_to(cr, leg2_x + 14.0 * scale, leg_y + 9.0 * scale);
    cairo_show_text(cr, "UDP");

    return finish_draw(cr);
}

int chart_draw_protocol_ports(cairo_t *cr, const stats_ctx_t *stats,
                              double x, double y, double width, double height)
{
    if (!cr || !stats || width <= 0.0 || height <= 0.0) {
        return PCAPSTAT_ERR_ARGS;
    }

    cairo_save(cr);
    cairo_rectangle(cr, x, y, width, height);
    cairo_clip(cr);

    const char *title_text = "Top 10 Destination Ports";

    /* Fetch Top 10 destination ports */
    const port_stats_t *top_ports[10];
    size_t count = stats_top_ports(stats, top_ports, 10);

    if (count == 0) {
        draw_empty_placeholder(cr, x, y, width, height, title_text,
                               "No destination port data available");
        return finish_draw(cr);
    }

    /* Fill background */
    cairo_set_source_rgb(cr, COLOR_BG_R, COLOR_BG_G, COLOR_BG_B);
    cairo_rectangle(cr, x, y, width, height);
    cairo_fill(cr);

    double scale = get_ui_scale(width);
    draw_chart_title(cr, x, y, scale, title_text);

    /* Bar labels, e.g. "443/tcp (HTTPS)", measured at the label font size */
    char port_lbls[10][64];
    double max_lbl_w = 0.0;
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.5 * scale);
    for (size_t i = 0; i < count; i++) {
        format_port_label(port_lbls[i], sizeof(port_lbls[i]), top_ports[i]);
        cairo_text_extents_t lbl_ext;
        cairo_text_extents(cr, port_lbls[i], &lbl_ext);
        if (lbl_ext.x_advance > max_lbl_w) {
            max_lbl_w = lbl_ext.x_advance;
        }
    }

    /* Margins: the left margin holds the port labels; widen it when the
     * longest label needs more room, keeping most of the box for bars. */
    double margin_left = 110.0 * scale;
    if (max_lbl_w + 16.0 * scale > margin_left) {
        margin_left = max_lbl_w + 16.0 * scale;
    }
    if (margin_left > width * 0.45) {
        margin_left = width * 0.45;
    }
    double margin_right = 50.0 * scale;
    double margin_top = 45.0 * scale;
    double margin_bottom = 30.0 * scale;

    double plot_x = x + margin_left;
    double plot_y = y + margin_top;
    double plot_w = width - margin_left - margin_right;
    double plot_h = height - margin_top - margin_bottom;

    if (plot_w <= 20.0 || plot_h <= 20.0) {
        cairo_restore(cr);
        return PCAPSTAT_ERR_ARGS;
    }

    uint64_t max_pkts = top_ports[0]->packets;
    if (max_pkts == 0) {
        max_pkts = 1;
    }
    double nice_max = calculate_nice_max((double)max_pkts);

    /* Draw vertical gridlines and X-axis labels */
    int num_x_ticks = 4;
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.0 * scale);

    for (int i = 0; i <= num_x_ticks; i++) {
        double tick_val = nice_max * ((double)i / (double)num_x_ticks);
        double grid_x = plot_x + plot_w * ((double)i / (double)num_x_ticks);

        /* Gridline */
        cairo_set_source_rgb(cr, COLOR_GRID_R, COLOR_GRID_G, COLOR_GRID_B);
        cairo_set_line_width(cr, 1.0);
        cairo_move_to(cr, grid_x, plot_y);
        cairo_line_to(cr, grid_x, plot_y + plot_h);
        cairo_stroke(cr);

        /* X-tick label */
        char lbl[32];
        format_axis_tick(lbl, sizeof(lbl), tick_val);
        cairo_text_extents_t ext;
        cairo_text_extents(cr, lbl, &ext);
        cairo_set_source_rgb(cr, COLOR_TEXT_LABEL_R, COLOR_TEXT_LABEL_G, COLOR_TEXT_LABEL_B);
        cairo_move_to(cr, grid_x - (ext.width / 2.0 + ext.x_bearing),
                          plot_y + plot_h + 14.0 * scale);
        cairo_show_text(cr, lbl);
    }

    /* Draw horizontal bars */
    double slot_h = plot_h / (double)count;
    double bar_h = slot_h * 0.65;
    if (bar_h > 24.0 * scale) {
        bar_h = 24.0 * scale;
    }

    for (size_t i = 0; i < count; i++) {
        const port_stats_t *p = top_ports[i];
        const char *port_lbl = port_lbls[i];

        double bar_y = plot_y + i * slot_h + (slot_h - bar_h) / 2.0;
        double bar_w = ((double)p->packets / nice_max) * plot_w;
        if (bar_w < 1.0) {
            bar_w = 1.0;
        }

        /* Port label on the left */
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 9.5 * scale);
        cairo_set_source_rgb(cr, COLOR_TEXT_TITLE_R, COLOR_TEXT_TITLE_G, COLOR_TEXT_TITLE_B);

        cairo_text_extents_t ext;
        cairo_text_extents(cr, port_lbl, &ext);
        cairo_move_to(cr, plot_x - ext.x_advance - 8.0 * scale,
                          bar_y + (bar_h / 2.0) - (ext.height / 2.0 + ext.y_bearing));
        cairo_show_text(cr, port_lbl);

        /* Bar fill */
        cairo_set_source_rgb(cr, COLOR_BAR_BLUE_R, COLOR_BAR_BLUE_G, COLOR_BAR_BLUE_B);
        cairo_rectangle(cr, plot_x, bar_y, bar_w, bar_h);
        cairo_fill(cr);

        /* Value label on the right */
        char cnt_buf[32];
        format_metric(cnt_buf, sizeof(cnt_buf), (double)p->packets);
        cairo_set_font_size(cr, 9.0 * scale);
        cairo_set_source_rgb(cr, COLOR_TEXT_LABEL_R, COLOR_TEXT_LABEL_G, COLOR_TEXT_LABEL_B);
        cairo_text_extents(cr, cnt_buf, &ext);
        cairo_move_to(cr, plot_x + bar_w + 6.0 * scale,
                          bar_y + (bar_h / 2.0) - (ext.height / 2.0 + ext.y_bearing));
        cairo_show_text(cr, cnt_buf);
    }

    /* Plot area border */
    cairo_set_source_rgb(cr, COLOR_AXIS_R, COLOR_AXIS_G, COLOR_AXIS_B);
    cairo_set_line_width(cr, 1.0);
    cairo_rectangle(cr, plot_x, plot_y, plot_w, plot_h);
    cairo_stroke(cr);

    return finish_draw(cr);
}

int chart_draw_packet_sizes(cairo_t *cr, const stats_ctx_t *stats,
                            double x, double y, double width, double height)
{
    if (!cr || !stats || width <= 0.0 || height <= 0.0) {
        return PCAPSTAT_ERR_ARGS;
    }

    cairo_save(cr);
    cairo_rectangle(cr, x, y, width, height);
    cairo_clip(cr);

    const char *title_text = "Packet Size Distribution";

    if (stats->total_packets == 0) {
        draw_empty_placeholder(cr, x, y, width, height, title_text,
                               "No packets in capture");
        return finish_draw(cr);
    }

    /* Fill background */
    cairo_set_source_rgb(cr, COLOR_BG_R, COLOR_BG_G, COLOR_BG_B);
    cairo_rectangle(cr, x, y, width, height);
    cairo_fill(cr);

    double scale = get_ui_scale(width);
    draw_chart_title(cr, x, y, scale, title_text);

    /* Margins */
    double margin_left = 60.0 * scale;
    double margin_right = 24.0 * scale;
    double margin_top = 45.0 * scale;
    double margin_bottom = 35.0 * scale;

    double plot_x = x + margin_left;
    double plot_y = y + margin_top;
    double plot_w = width - margin_left - margin_right;
    double plot_h = height - margin_top - margin_bottom;

    if (plot_w <= 20.0 || plot_h <= 20.0) {
        cairo_restore(cr);
        return PCAPSTAT_ERR_ARGS;
    }

    /* Find maximum count across the 7 bins */
    uint64_t max_count = 0;
    for (int i = 0; i < STATS_PACKET_SIZE_BINS; i++) {
        if (stats->packet_size_histogram[i] > max_count) {
            max_count = stats->packet_size_histogram[i];
        }
    }
    if (max_count == 0) {
        max_count = 1;
    }
    double nice_max = calculate_nice_max((double)max_count);

    /* Horizontal gridlines and Y-axis labels */
    int num_y_ticks = 4;
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.0 * scale);

    for (int i = 0; i <= num_y_ticks; i++) {
        double tick_val = nice_max * ((double)i / (double)num_y_ticks);
        double grid_y = plot_y + plot_h - (plot_h * ((double)i / (double)num_y_ticks));

        cairo_set_source_rgb(cr, COLOR_GRID_R, COLOR_GRID_G, COLOR_GRID_B);
        cairo_set_line_width(cr, (i == 0) ? 1.5 : 1.0);
        cairo_move_to(cr, plot_x, grid_y);
        cairo_line_to(cr, plot_x + plot_w, grid_y);
        cairo_stroke(cr);

        char lbl[32];
        format_axis_tick(lbl, sizeof(lbl), tick_val);
        cairo_text_extents_t ext;
        cairo_text_extents(cr, lbl, &ext);
        cairo_set_source_rgb(cr, COLOR_TEXT_LABEL_R, COLOR_TEXT_LABEL_G, COLOR_TEXT_LABEL_B);
        cairo_move_to(cr, plot_x - ext.x_advance - 6.0 * scale,
                          grid_y - (ext.height / 2.0 + ext.y_bearing));
        cairo_show_text(cr, lbl);
    }

    /* Bins (frame wire length): [0,64) [64,128) [128,256) [256,512)
     * [512,1024) [1024,1514) [1514,inf), see STATS_PACKET_SIZE_BINS. */
    static const char *bin_labels[STATS_PACKET_SIZE_BINS] = {
        "<64", "64-127", "128-255", "256-511", "512-1023", "1024-1513", ">=1514"
    };

    /* Draw vertical histogram bars */
    double slot_w = plot_w / (double)STATS_PACKET_SIZE_BINS;
    double bar_w = slot_w * 0.62;

    for (int i = 0; i < STATS_PACKET_SIZE_BINS; i++) {
        uint64_t count = stats->packet_size_histogram[i];
        double bar_h = ((double)count / nice_max) * plot_h;
        double bar_x = plot_x + i * slot_w + (slot_w - bar_w) / 2.0;
        double bar_y = plot_y + plot_h - bar_h;

        /* Bar fill */
        cairo_set_source_rgb(cr, COLOR_HIST_R, COLOR_HIST_G, COLOR_HIST_B);
        cairo_rectangle(cr, bar_x, bar_y, bar_w, bar_h);
        cairo_fill(cr);

        /* Percentage above bar */
        if (count > 0 && stats->total_packets > 0) {
            double pct = ((double)count / (double)stats->total_packets) * 100.0;
            char pct_buf[32];
            snprintf(pct_buf, sizeof(pct_buf), "%.1f%%", pct);

            cairo_set_font_size(cr, 8.5 * scale);
            cairo_set_source_rgb(cr, COLOR_TEXT_LABEL_R, COLOR_TEXT_LABEL_G, COLOR_TEXT_LABEL_B);
            cairo_text_extents_t ext;
            cairo_text_extents(cr, pct_buf, &ext);
            cairo_move_to(cr, bar_x + (bar_w / 2.0) - (ext.width / 2.0 + ext.x_bearing),
                              bar_y - 4.0 * scale);
            cairo_show_text(cr, pct_buf);
        }

        /* Bin label below bar */
        cairo_set_font_size(cr, 8.5 * scale);
        cairo_set_source_rgb(cr, COLOR_TEXT_TITLE_R, COLOR_TEXT_TITLE_G, COLOR_TEXT_TITLE_B);
        cairo_text_extents_t ext;
        cairo_text_extents(cr, bin_labels[i], &ext);
        cairo_move_to(cr, bar_x + (bar_w / 2.0) - (ext.width / 2.0 + ext.x_bearing),
                          plot_y + plot_h + 14.0 * scale);
        cairo_show_text(cr, bin_labels[i]);
    }

    /* Plot area border */
    cairo_set_source_rgb(cr, COLOR_AXIS_R, COLOR_AXIS_G, COLOR_AXIS_B);
    cairo_set_line_width(cr, 1.0);
    cairo_rectangle(cr, plot_x, plot_y, plot_w, plot_h);
    cairo_stroke(cr);

    return finish_draw(cr);
}

int chart_draw_tcp_flags(cairo_t *cr, const stats_ctx_t *stats,
                         double x, double y, double width, double height)
{
    if (!cr || !stats || width <= 0.0 || height <= 0.0) {
        return PCAPSTAT_ERR_ARGS;
    }

    cairo_save(cr);
    cairo_rectangle(cr, x, y, width, height);
    cairo_clip(cr);

    const char *title_text = "TCP Flag Distribution";

    if (stats->tcp_packets == 0) {
        draw_empty_placeholder(cr, x, y, width, height, title_text,
                               "No TCP packets in capture");
        return finish_draw(cr);
    }

    /* Fill background */
    cairo_set_source_rgb(cr, COLOR_BG_R, COLOR_BG_G, COLOR_BG_B);
    cairo_rectangle(cr, x, y, width, height);
    cairo_fill(cr);

    double scale = get_ui_scale(width);
    draw_chart_title(cr, x, y, scale, title_text);

    /* Margins */
    double margin_left = 60.0 * scale;
    double margin_right = 24.0 * scale;
    double margin_top = 45.0 * scale;
    double margin_bottom = 35.0 * scale;

    double plot_x = x + margin_left;
    double plot_y = y + margin_top;
    double plot_w = width - margin_left - margin_right;
    double plot_h = height - margin_top - margin_bottom;

    if (plot_w <= 20.0 || plot_h <= 20.0) {
        cairo_restore(cr);
        return PCAPSTAT_ERR_ARGS;
    }

    static const char *flag_names[TCP_FLAG_BARS] = {
        "SYN", "SYN-ACK", "ACK", "FIN", "RST", "PSH", "URG", "Suspicious"
    };

    /* "Suspicious" = flag combinations that never occur in legitimate
     * traffic: NULL + Xmas + SYN+FIN + SYN+RST (same sum as the report's
     * flag table; a SYN+FIN+RST packet is in both SYN terms). */
    uint64_t counts[TCP_FLAG_BARS] = {
        stats->syn,
        stats->syn_ack,
        stats->ack,
        stats->fin,
        stats->rst,
        stats->psh,
        stats->urg,
        stats->null_scan_pkts + stats->xmas_scan_pkts +
            stats->syn_fin_pkts + stats->syn_rst_pkts
    };

    uint64_t max_count = 0;
    for (int i = 0; i < TCP_FLAG_BARS; i++) {
        if (counts[i] > max_count) {
            max_count = counts[i];
        }
    }
    if (max_count == 0) {
        max_count = 1;
    }
    double nice_max = calculate_nice_max((double)max_count);

    /* Horizontal gridlines and Y-axis labels */
    int num_y_ticks = 4;
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.0 * scale);

    for (int i = 0; i <= num_y_ticks; i++) {
        double tick_val = nice_max * ((double)i / (double)num_y_ticks);
        double grid_y = plot_y + plot_h - (plot_h * ((double)i / (double)num_y_ticks));

        cairo_set_source_rgb(cr, COLOR_GRID_R, COLOR_GRID_G, COLOR_GRID_B);
        cairo_set_line_width(cr, (i == 0) ? 1.5 : 1.0);
        cairo_move_to(cr, plot_x, grid_y);
        cairo_line_to(cr, plot_x + plot_w, grid_y);
        cairo_stroke(cr);

        char lbl[32];
        format_axis_tick(lbl, sizeof(lbl), tick_val);
        cairo_text_extents_t ext;
        cairo_text_extents(cr, lbl, &ext);
        cairo_set_source_rgb(cr, COLOR_TEXT_LABEL_R, COLOR_TEXT_LABEL_G, COLOR_TEXT_LABEL_B);
        cairo_move_to(cr, plot_x - ext.x_advance - 6.0 * scale,
                          grid_y - (ext.height / 2.0 + ext.y_bearing));
        cairo_show_text(cr, lbl);
    }

    /* Draw vertical flag bars */
    double slot_w = plot_w / (double)TCP_FLAG_BARS;
    double bar_w = slot_w * 0.62;

    for (int i = 0; i < TCP_FLAG_BARS; i++) {
        double bar_h = ((double)counts[i] / nice_max) * plot_h;
        double bar_x = plot_x + i * slot_w + (slot_w - bar_w) / 2.0;
        double bar_y = plot_y + plot_h - bar_h;

        /* Bar fill using distinct flag color */
        cairo_set_source_rgb(cr, TCP_FLAG_COLORS[i][0],
                                 TCP_FLAG_COLORS[i][1],
                                 TCP_FLAG_COLORS[i][2]);
        cairo_rectangle(cr, bar_x, bar_y, bar_w, bar_h);
        cairo_fill(cr);

        /* Percentage / count above bar */
        if (counts[i] > 0 && stats->tcp_packets > 0) {
            double pct = ((double)counts[i] / (double)stats->tcp_packets) * 100.0;
            char pct_buf[32];
            snprintf(pct_buf, sizeof(pct_buf), "%.1f%%", pct);

            cairo_set_font_size(cr, 8.5 * scale);
            cairo_set_source_rgb(cr, COLOR_TEXT_LABEL_R, COLOR_TEXT_LABEL_G, COLOR_TEXT_LABEL_B);
            cairo_text_extents_t ext;
            cairo_text_extents(cr, pct_buf, &ext);
            cairo_move_to(cr, bar_x + (bar_w / 2.0) - (ext.width / 2.0 + ext.x_bearing),
                              bar_y - 4.0 * scale);
            cairo_show_text(cr, pct_buf);
        }

        /* Flag label below bar */
        cairo_set_font_size(cr, 9.0 * scale);
        cairo_set_source_rgb(cr, COLOR_TEXT_TITLE_R, COLOR_TEXT_TITLE_G, COLOR_TEXT_TITLE_B);
        cairo_text_extents_t ext;
        cairo_text_extents(cr, flag_names[i], &ext);
        cairo_move_to(cr, bar_x + (bar_w / 2.0) - (ext.width / 2.0 + ext.x_bearing),
                          plot_y + plot_h + 14.0 * scale);
        cairo_show_text(cr, flag_names[i]);
    }

    /* Plot area border */
    cairo_set_source_rgb(cr, COLOR_AXIS_R, COLOR_AXIS_G, COLOR_AXIS_B);
    cairo_set_line_width(cr, 1.0);
    cairo_rectangle(cr, plot_x, plot_y, plot_w, plot_h);
    cairo_stroke(cr);

    return finish_draw(cr);
}

/* -------------------------------------------------------------------
 * Standalone PNG Export Helper and Wrappers
 * ------------------------------------------------------------------- */

typedef int (*chart_draw_fn)(cairo_t *cr, const stats_ctx_t *stats,
                             double x, double y, double width, double height);

/**
 * @brief Helper that creates an image surface, renders a chart, and writes to PNG.
 */
static int export_chart_to_png(const stats_ctx_t *stats,
                               const char *file_path,
                               int width, int height,
                               chart_draw_fn draw_fn)
{
    if (!stats || !file_path) {
        return PCAPSTAT_ERR_ARGS;
    }

    int img_w = (width > 0) ? width : CHART_DEFAULT_PNG_WIDTH;
    int img_h = (height > 0) ? height : CHART_DEFAULT_PNG_HEIGHT;

    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, img_w, img_h);
    if (!surface || cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        if (surface) {
            cairo_surface_destroy(surface);
        }
        return PCAPSTAT_ERR_NOMEM;
    }

    cairo_t *cr = cairo_create(surface);
    if (!cr || cairo_status(cr) != CAIRO_STATUS_SUCCESS) {
        if (cr) {
            cairo_destroy(cr);
        }
        cairo_surface_destroy(surface);
        return PCAPSTAT_ERR_NOMEM;
    }

    int rc = draw_fn(cr, stats, 0.0, 0.0, (double)img_w, (double)img_h);
    if (rc != PCAPSTAT_OK) {
        goto cleanup;
    }

    /* A failed Cairo operation puts the context (or surface) into a
     * sticky error state and turns later drawing into no-ops. */
    cairo_surface_flush(surface);
    if (cairo_status(cr) != CAIRO_STATUS_SUCCESS ||
        cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        rc = PCAPSTAT_ERR_RENDER;
        goto cleanup;
    }

    cairo_status_t write_status = cairo_surface_write_to_png(surface, file_path);
    if (write_status != CAIRO_STATUS_SUCCESS) {
        rc = PCAPSTAT_ERR_IO;
        goto cleanup;
    }

    rc = PCAPSTAT_OK;

cleanup:
    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    return rc;
}

int chart_export_traffic_timeline_png(const stats_ctx_t *stats,
                                      const char *file_path,
                                      int width, int height)
{
    return export_chart_to_png(stats, file_path, width, height, chart_draw_traffic_timeline);
}

int chart_export_protocol_ports_png(const stats_ctx_t *stats,
                                    const char *file_path,
                                    int width, int height)
{
    return export_chart_to_png(stats, file_path, width, height, chart_draw_protocol_ports);
}

int chart_export_packet_sizes_png(const stats_ctx_t *stats,
                                  const char *file_path,
                                  int width, int height)
{
    return export_chart_to_png(stats, file_path, width, height, chart_draw_packet_sizes);
}

int chart_export_tcp_flags_png(const stats_ctx_t *stats,
                               const char *file_path,
                               int width, int height)
{
    return export_chart_to_png(stats, file_path, width, height, chart_draw_tcp_flags);
}

/**
 * @brief Build "<dir>/<name>" into @p buf, ignoring trailing slashes of
 *        @p dir ("out/" and "out" give "out/<name>"; "/" gives "/<name>").
 *
 * Same rule as join_path() in main.c, so the files written here match the
 * paths main prints.
 *
 * @return PCAPSTAT_OK, or PCAPSTAT_ERR_ARGS if @p dir is empty or the
 *         result does not fit in @p buf_len bytes.
 */
static int join_output_path(char *buf, size_t buf_len, const char *dir,
                            const char *name)
{
    size_t dlen = strlen(dir);
    while (dlen > 1 && dir[dlen - 1] == '/') {
        dlen--;
    }
    if (dlen == 0 || dlen >= buf_len) {
        return PCAPSTAT_ERR_ARGS;
    }

    const char *sep = (dlen == 1 && dir[0] == '/') ? "" : "/";
    int n = snprintf(buf, buf_len, "%.*s%s%s", (int)dlen, dir, sep, name);
    if (n < 0 || (size_t)n >= buf_len) {
        return PCAPSTAT_ERR_ARGS;
    }
    return PCAPSTAT_OK;
}

int charts_generate_all(const stats_ctx_t *stats, const char *output_dir)
{
    if (!stats || !output_dir) {
        return PCAPSTAT_ERR_ARGS;
    }

    char path[PCAPSTAT_MAX_PATH];

    /* 1. Traffic Timeline */
    int rc = join_output_path(path, sizeof(path), output_dir, CHART_FILE_TRAFFIC_TIMELINE);
    if (rc != PCAPSTAT_OK) {
        return rc;
    }
    rc = chart_export_traffic_timeline_png(stats, path, 0, 0);
    if (rc != PCAPSTAT_OK) {
        return rc;
    }

    /* 2. Top Destination Ports */
    rc = join_output_path(path, sizeof(path), output_dir, CHART_FILE_PROTOCOL_PORTS);
    if (rc != PCAPSTAT_OK) {
        return rc;
    }
    rc = chart_export_protocol_ports_png(stats, path, 0, 0);
    if (rc != PCAPSTAT_OK) {
        return rc;
    }

    /* 3. Packet Sizes Histogram */
    rc = join_output_path(path, sizeof(path), output_dir, CHART_FILE_PACKET_SIZES);
    if (rc != PCAPSTAT_OK) {
        return rc;
    }
    rc = chart_export_packet_sizes_png(stats, path, 0, 0);
    if (rc != PCAPSTAT_OK) {
        return rc;
    }

    /* 4. TCP Flags */
    rc = join_output_path(path, sizeof(path), output_dir, CHART_FILE_TCP_FLAGS);
    if (rc != PCAPSTAT_OK) {
        return rc;
    }
    rc = chart_export_tcp_flags_png(stats, path, 0, 0);
    if (rc != PCAPSTAT_OK) {
        return rc;
    }

    return PCAPSTAT_OK;
}
