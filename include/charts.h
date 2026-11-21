/**
 * @file charts.h
 * @brief Vector chart generation and PNG export using libcairo.
 *
 * Provides reusable vector drawing routines that render into an arbitrary
 * bounding box within an existing cairo_t context (for direct vector embedding
 * into PDF reports or image surfaces) as well as standalone PNG export wrappers.
 *
 * State preservation guarantee:
 * Every vector drawing function isolates its modifications to the Cairo context
 * by invoking cairo_save() on entry and cairo_restore() before returning, ensuring
 * that the caller's transformation matrix, clip region, font setup, and pen state
 * remain completely unmodified.
 *
 * All functions handle empty datasets gracefully without division-by-zero errors,
 * rendering a clean placeholder message within the bounding box.
 *
 * Error reporting: Cairo errors are sticky (a failed operation puts the context
 * into an error state and later drawing becomes a no-op). Every drawing function
 * checks cairo_status() after restoring the caller's state and returns
 * PCAPSTAT_ERR_RENDER if the context is in an error state, including one that
 * was already in error on entry.
 *
 * Value-axis tick labels are the axis maximum split into quarters; below 1000
 * they are printed exactly with "%g" (e.g. "0 0.25 0.5 0.75 1", "0 2.5 5 7.5 10"),
 * from 1000 up in compact metric form ("2.5K", "1.2M").
 */

#ifndef PCAPSTAT_CHARTS_H
#define PCAPSTAT_CHARTS_H

#include "common.h"
#include "stats.h"

#include <cairo.h>

/** @brief Default width in pixels for exported PNG charts. */
#define CHART_DEFAULT_PNG_WIDTH  800

/** @brief Default height in pixels for exported PNG charts. */
#define CHART_DEFAULT_PNG_HEIGHT 500

/** @brief File name for the traffic timeline PNG chart. */
#define CHART_FILE_TRAFFIC_TIMELINE "traffic_timeline.png"

/** @brief File name for the protocol destination ports PNG chart. */
#define CHART_FILE_PROTOCOL_PORTS   "protocol_ports.png"

/** @brief File name for the packet size distribution histogram PNG chart. */
#define CHART_FILE_PACKET_SIZES     "packet_sizes.png"

/** @brief File name for the TCP flag distribution PNG chart. */
#define CHART_FILE_TCP_FLAGS        "tcp_flags.png"

/* -------------------------------------------------------------------
 * Reusable Vector Drawing Functions
 * ------------------------------------------------------------------- */

/**
 * @brief Render traffic packet rate over time (TCP vs UDP line chart).
 *
 * Plots packets/sec (`packets / span_sec` per bucket) for TCP (blue) and
 * UDP (orange) over the finalized sparse timeline, with axes, gridlines and
 * a color legend.
 *
 * - Consecutive buckets are joined at their midpoints. Where a bucket does
 *   not start where the previous one ends (`sec > prev.sec + prev.span_sec`,
 *   i.e. no packets in between), both lines drop to 0 at the end of the
 *   previous bucket and rise from 0 at the start of the next one. A timeline
 *   with a single bucket is drawn as a flat segment over that bucket.
 * - The X axis runs from the first bucket's start to the last bucket's end;
 *   tick labels are offsets from the start whose unit follows the total span:
 *   "+12s" / "+2.5s" (< 60 s), "+05:30" (< 1 h), "+3h05m" (< 1 day),
 *   "+2d04h" otherwise. Any bucket seconds representable in int64_t
 *   (timestamps up to about +/-9e18 s) are handled without overflow; labels
 *   are never negative.
 *
 * If stats->timeline_count == 0 (no packet with a usable timestamp), displays
 * a safe placeholder message ("No timeline data available").
 *
 * @param cr     Target Cairo context (borrowed; state is saved and restored).
 * @param stats  Finalized statistics context (borrowed).
 * @param x      X coordinate of the bounding box origin.
 * @param y      Y coordinate of the bounding box origin.
 * @param width  Width of the bounding box (> 0).
 * @param height Height of the bounding box (> 0).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if cr or stats is NULL, dimensions are non-positive,
 *         or the box is too small to hold the plot area,
 *         PCAPSTAT_ERR_RENDER if @p cr is in a Cairo error state afterwards.
 */
int chart_draw_traffic_timeline(cairo_t *cr, const stats_ctx_t *stats,
                                double x, double y, double width, double height);

/**
 * @brief Render horizontal bar chart of Top 10 destination ports and services.
 *
 * Shows the Top 10 (protocol, destination port) pairs from stats_top_ports(),
 * sorted descending by packet volume. Each bar is labeled
 * "<port>/<proto> (<service>)", e.g. "443/tcp (HTTPS)" or "53/udp (DNS)", so
 * TCP and UDP traffic to the same port number appear as two distinguishable
 * bars. The left margin widens (up to 45 % of the box) to fit the longest label.
 *
 * If no destination ports were recorded, displays a safe placeholder message
 * ("No destination port data available").
 *
 * @param cr     Target Cairo context (borrowed; state is saved and restored).
 * @param stats  Finalized statistics context (borrowed).
 * @param x      X coordinate of the bounding box origin.
 * @param y      Y coordinate of the bounding box origin.
 * @param width  Width of the bounding box (> 0).
 * @param height Height of the bounding box (> 0).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if cr or stats is NULL, dimensions are non-positive,
 *         or the box is too small to hold the plot area,
 *         PCAPSTAT_ERR_RENDER if @p cr is in a Cairo error state afterwards.
 */
int chart_draw_protocol_ports(cairo_t *cr, const stats_ctx_t *stats,
                              double x, double y, double width, double height);

/**
 * @brief Render vertical bar histogram of the 7 packet size bins.
 *
 * Visualizes stats->packet_size_histogram (frame wire length, all packets
 * including malformed ones) as counts with percentages of total_packets.
 * Bins are half-open byte ranges
 * [0,64) [64,128) [128,256) [256,512) [512,1024) [1024,1514) [1514,inf),
 * labeled "<64", "64-127", "128-255", "256-511", "512-1023", "1024-1513",
 * ">=1514".
 *
 * If stats->total_packets == 0, displays a safe placeholder message
 * ("No packets in capture").
 *
 * @param cr     Target Cairo context (borrowed; state is saved and restored).
 * @param stats  Finalized statistics context (borrowed).
 * @param x      X coordinate of the bounding box origin.
 * @param y      Y coordinate of the bounding box origin.
 * @param width  Width of the bounding box (> 0).
 * @param height Height of the bounding box (> 0).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if cr or stats is NULL, dimensions are non-positive,
 *         or the box is too small to hold the plot area,
 *         PCAPSTAT_ERR_RENDER if @p cr is in a Cairo error state afterwards.
 */
int chart_draw_packet_sizes(cairo_t *cr, const stats_ctx_t *stats,
                            double x, double y, double width, double height);

/**
 * @brief Render bar chart of TCP flag occurrences.
 *
 * Plots 8 bars with counts and percentages of stats->tcp_packets:
 * SYN (pure SYN, ACK clear), SYN-ACK, ACK (includes SYN-ACK), FIN, RST, PSH,
 * URG, and a dark-red "Suspicious" bar for flag combinations that do not occur
 * in legitimate traffic: null_scan_pkts + xmas_scan_pkts + syn_fin_pkts +
 * syn_rst_pkts (a SYN+FIN+RST packet counts in both SYN terms). A packet can
 * appear in several bars, so the percentages do not sum to 100 %.
 *
 * If stats->tcp_packets == 0, displays a safe placeholder message
 * ("No TCP packets in capture").
 *
 * @param cr     Target Cairo context (borrowed; state is saved and restored).
 * @param stats  Finalized statistics context (borrowed).
 * @param x      X coordinate of the bounding box origin.
 * @param y      Y coordinate of the bounding box origin.
 * @param width  Width of the bounding box (> 0).
 * @param height Height of the bounding box (> 0).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if cr or stats is NULL, dimensions are non-positive,
 *         or the box is too small to hold the plot area,
 *         PCAPSTAT_ERR_RENDER if @p cr is in a Cairo error state afterwards.
 */
int chart_draw_tcp_flags(cairo_t *cr, const stats_ctx_t *stats,
                         double x, double y, double width, double height);

/* -------------------------------------------------------------------
 * PNG Export Wrappers
 * ------------------------------------------------------------------- */

/**
 * @brief Export traffic timeline chart to a standalone PNG image.
 *
 * Allocates a Cairo image surface with a white background, renders the chart,
 * writes the PNG to @p file_path, and frees all Cairo resources.
 *
 * @param stats     Finalized statistics context (borrowed).
 * @param file_path Destination PNG file path (caller-owned).
 * @param width     Image width in pixels (if <= 0, uses CHART_DEFAULT_PNG_WIDTH).
 * @param height    Image height in pixels (if <= 0, uses CHART_DEFAULT_PNG_HEIGHT).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if stats or file_path is NULL, or the image is too
 *         small to hold the plot area,
 *         PCAPSTAT_ERR_NOMEM if surface or context allocation fails,
 *         PCAPSTAT_ERR_RENDER if the Cairo context or surface is in an error
 *         state after drawing (nothing is written),
 *         PCAPSTAT_ERR_IO if writing the PNG file fails.
 */
int chart_export_traffic_timeline_png(const stats_ctx_t *stats,
                                      const char *file_path,
                                      int width, int height);

/**
 * @brief Export Top 10 destination ports chart to a standalone PNG image.
 *
 * Allocates a Cairo image surface with a white background, renders the chart,
 * writes the PNG to @p file_path, and frees all Cairo resources.
 *
 * @param stats     Finalized statistics context (borrowed).
 * @param file_path Destination PNG file path (caller-owned).
 * @param width     Image width in pixels (if <= 0, uses CHART_DEFAULT_PNG_WIDTH).
 * @param height    Image height in pixels (if <= 0, uses CHART_DEFAULT_PNG_HEIGHT).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if stats or file_path is NULL, or the image is too
 *         small to hold the plot area,
 *         PCAPSTAT_ERR_NOMEM if surface or context allocation fails,
 *         PCAPSTAT_ERR_RENDER if the Cairo context or surface is in an error
 *         state after drawing (nothing is written),
 *         PCAPSTAT_ERR_IO if writing the PNG file fails.
 */
int chart_export_protocol_ports_png(const stats_ctx_t *stats,
                                    const char *file_path,
                                    int width, int height);

/**
 * @brief Export packet size histogram to a standalone PNG image.
 *
 * Allocates a Cairo image surface with a white background, renders the chart,
 * writes the PNG to @p file_path, and frees all Cairo resources.
 *
 * @param stats     Finalized statistics context (borrowed).
 * @param file_path Destination PNG file path (caller-owned).
 * @param width     Image width in pixels (if <= 0, uses CHART_DEFAULT_PNG_WIDTH).
 * @param height    Image height in pixels (if <= 0, uses CHART_DEFAULT_PNG_HEIGHT).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if stats or file_path is NULL, or the image is too
 *         small to hold the plot area,
 *         PCAPSTAT_ERR_NOMEM if surface or context allocation fails,
 *         PCAPSTAT_ERR_RENDER if the Cairo context or surface is in an error
 *         state after drawing (nothing is written),
 *         PCAPSTAT_ERR_IO if writing the PNG file fails.
 */
int chart_export_packet_sizes_png(const stats_ctx_t *stats,
                                  const char *file_path,
                                  int width, int height);

/**
 * @brief Export TCP flags distribution chart to a standalone PNG image.
 *
 * Allocates a Cairo image surface with a white background, renders the chart,
 * writes the PNG to @p file_path, and frees all Cairo resources.
 *
 * @param stats     Finalized statistics context (borrowed).
 * @param file_path Destination PNG file path (caller-owned).
 * @param width     Image width in pixels (if <= 0, uses CHART_DEFAULT_PNG_WIDTH).
 * @param height    Image height in pixels (if <= 0, uses CHART_DEFAULT_PNG_HEIGHT).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if stats or file_path is NULL, or the image is too
 *         small to hold the plot area,
 *         PCAPSTAT_ERR_NOMEM if surface or context allocation fails,
 *         PCAPSTAT_ERR_RENDER if the Cairo context or surface is in an error
 *         state after drawing (nothing is written),
 *         PCAPSTAT_ERR_IO if writing the PNG file fails.
 */
int chart_export_tcp_flags_png(const stats_ctx_t *stats,
                               const char *file_path,
                               int width, int height);

/**
 * @brief Export all 4 standard charts to PNG files in the specified directory.
 *
 * Generates:
 * - `<output_dir>/traffic_timeline.png`
 * - `<output_dir>/protocol_ports.png`
 * - `<output_dir>/packet_sizes.png`
 * - `<output_dir>/tcp_flags.png`
 *
 * Trailing slashes of @p output_dir are ignored ("out/" and "out" give
 * "out/traffic_timeline.png"; "/" gives "/traffic_timeline.png"), the same
 * rule main.c uses for the paths it prints. Uses default PNG dimensions.
 * Stops and returns on first failure; files written before it are kept.
 *
 * @param stats      Finalized statistics context (borrowed).
 * @param output_dir Target directory path (caller-owned, must exist).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if stats or output_dir is NULL, output_dir is
 *         empty, or a joined path does not fit in PCAPSTAT_MAX_PATH bytes,
 *         PCAPSTAT_ERR_IO / PCAPSTAT_ERR_NOMEM / PCAPSTAT_ERR_RENDER from the
 *         export functions on failure.
 */
int charts_generate_all(const stats_ctx_t *stats, const char *output_dir);

#endif /* PCAPSTAT_CHARTS_H */
