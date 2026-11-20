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
 * Plots packets/sec for TCP (blue) and UDP (orange) over the finalized
 * sparse timeline, with axes, gridlines, compact unit formatting (e.g. 1.2K),
 * and a color legend.
 *
 * If stats->timeline_count == 0 or no packets are present, displays a safe
 * placeholder message ("No timeline data available").
 *
 * @param cr     Target Cairo context (borrowed; state is saved and restored).
 * @param stats  Finalized statistics context (borrowed).
 * @param x      X coordinate of the bounding box origin.
 * @param y      Y coordinate of the bounding box origin.
 * @param width  Width of the bounding box (> 0).
 * @param height Height of the bounding box (> 0).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if cr or stats is NULL or dimensions are non-positive,
 *         PCAPSTAT_ERR_RENDER on Cairo rendering error.
 */
int chart_draw_traffic_timeline(cairo_t *cr, const stats_ctx_t *stats,
                                double x, double y, double width, double height);

/**
 * @brief Render horizontal bar chart of Top 10 destination ports and services.
 *
 * Shows the Top 10 destination ports sorted descending by packet volume,
 * labeled with port number and standard service name (e.g., "443 (HTTPS)").
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
 *         PCAPSTAT_ERR_ARGS if cr or stats is NULL or dimensions are non-positive,
 *         PCAPSTAT_ERR_RENDER on Cairo rendering error.
 */
int chart_draw_protocol_ports(cairo_t *cr, const stats_ctx_t *stats,
                              double x, double y, double width, double height);

/**
 * @brief Render vertical bar histogram of the 7 packet size bins.
 *
 * Visualizes packet count and percentage across standard size bins:
 * (<64, 64-127, 128-255, 256-511, 512-1023, 1024-1513, >=1514 bytes).
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
 *         PCAPSTAT_ERR_ARGS if cr or stats is NULL or dimensions are non-positive,
 *         PCAPSTAT_ERR_RENDER on Cairo rendering error.
 */
int chart_draw_packet_sizes(cairo_t *cr, const stats_ctx_t *stats,
                            double x, double y, double width, double height);

/**
 * @brief Render bar chart of TCP flag occurrences.
 *
 * Plots counts and percentages for TCP flags: SYN, SYN-ACK, ACK, FIN, RST,
 * PSH, and URG.
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
 *         PCAPSTAT_ERR_ARGS if cr or stats is NULL or dimensions are non-positive,
 *         PCAPSTAT_ERR_RENDER on Cairo rendering error.
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
 *         PCAPSTAT_ERR_ARGS if stats or file_path is NULL,
 *         PCAPSTAT_ERR_NOMEM if surface or context allocation fails,
 *         PCAPSTAT_ERR_IO if writing PNG file fails,
 *         PCAPSTAT_ERR_RENDER on Cairo rendering error.
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
 *         PCAPSTAT_ERR_ARGS if stats or file_path is NULL,
 *         PCAPSTAT_ERR_NOMEM if surface or context allocation fails,
 *         PCAPSTAT_ERR_IO if writing PNG file fails,
 *         PCAPSTAT_ERR_RENDER on Cairo rendering error.
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
 *         PCAPSTAT_ERR_ARGS if stats or file_path is NULL,
 *         PCAPSTAT_ERR_NOMEM if surface or context allocation fails,
 *         PCAPSTAT_ERR_IO if writing PNG file fails,
 *         PCAPSTAT_ERR_RENDER on Cairo rendering error.
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
 *         PCAPSTAT_ERR_ARGS if stats or file_path is NULL,
 *         PCAPSTAT_ERR_NOMEM if surface or context allocation fails,
 *         PCAPSTAT_ERR_IO if writing PNG file fails,
 *         PCAPSTAT_ERR_RENDER on Cairo rendering error.
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
 * Uses default PNG dimensions. Stops and returns on first failure.
 *
 * @param stats      Finalized statistics context (borrowed).
 * @param output_dir Target directory path (caller-owned, must exist).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if stats or output_dir is NULL,
 *         PCAPSTAT_ERR_IO / PCAPSTAT_ERR_NOMEM / PCAPSTAT_ERR_RENDER on failure.
 */
int charts_generate_all(const stats_ctx_t *stats, const char *output_dir);

#endif /* PCAPSTAT_CHARTS_H */
