/**
 * @file report.h
 * @brief Multi-page PDF report generator using libcairo.
 *
 * Generates a polished, multi-page A4 PDF report summarizing capture metadata,
 * key performance indicators (KPIs), traffic characteristics (top talkers,
 * ports, flows), embedded vector charts, and detected security anomalies.
 *
 * Memory ownership:
 * - All input structures (@c cfg, @c stats, @c anomalies) and strings (@c pdf_path)
 *   are borrowed and remain owned by the caller.
 * - All Cairo rendering resources (PDF surface, context, patterns, fonts) are
 *   allocated and released internally by report_generate().
 * - No caller-visible heap allocations persist across report_generate().
 */

#ifndef PCAPSTAT_REPORT_H
#define PCAPSTAT_REPORT_H

#include "anomaly.h"
#include "cli.h"
#include "common.h"
#include "stats.h"

/** @brief Standard ISO A4 page width in typographic points (72 points/inch). */
#define REPORT_PAGE_WIDTH   595.0

/** @brief Standard ISO A4 page height in typographic points (72 points/inch). */
#define REPORT_PAGE_HEIGHT  842.0

/** @brief Default page margin in typographic points. */
#define REPORT_PAGE_MARGIN   40.0

/** @brief Default output filename for the generated PDF report. */
#define REPORT_DEFAULT_FILENAME "report.pdf"

/**
 * @brief Format a capture duration for humans.
 *
 * Below one minute: `"12.34 s"`. Otherwise whole seconds as `"HH:MM:SS"`,
 * prefixed with the day count once it reaches one day: `"3d 04:05:06"`.
 * Negative or non-finite input is treated as 0.
 *
 * @param seconds Duration in seconds (e.g. stats_ctx_t::duration_sec).
 * @param buf     Caller-owned output buffer; always NUL-terminated when
 *                @p sz > 0 (truncated if too small; 32 bytes suffice).
 * @param sz      Size of @p buf. Nothing is written if @p buf is NULL or
 *                @p sz is 0.
 */
void report_format_duration(double seconds, char *buf, size_t sz);

/**
 * @brief Format a bit rate with a decimal SI unit.
 *
 * `"%.0f bps"` below 1000, `"%.1f kbps"` below 1e6, `"%.2f Mbps"` below
 * 1e9, else `"%.2f Gbps"`. Negative or non-finite input is treated as 0.
 *
 * @param bits_per_sec Rate in BITS per second (stats_ctx_t::avg_bps).
 * @param buf          Caller-owned output buffer; always NUL-terminated
 *                     when @p sz > 0.
 * @param sz           Size of @p buf. Nothing is written if @p buf is NULL
 *                     or @p sz is 0.
 */
void report_format_bitrate(double bits_per_sec, char *buf, size_t sz);

/**
 * @brief Generate a comprehensive multi-page PDF report.
 *
 * Emits an A4 (595 x 842 pt) multi-page PDF document containing:
 * - Page 1 (Executive Summary): Title, capture file list (`"(none)"` when
 *   @p cfg lists no input files), generation metadata, and KPI cards/tables:
 *   volume, duration (report_format_duration()), packet and bit rate
 *   (report_format_bitrate()), protocol share, flows/hosts, anomaly summary,
 *   and TCP health (global stats_ctx_t::tcp_retransmissions over all flows,
 *   with out-of-order segments in the subtext). The protocol table has the
 *   rows TCP, UDP, Other IP, Non-IP frames (ARP/LLDP/...), Malformed and
 *   Total (the first five sum to Total, see the stats.h invariant).
 * - Page 2 (Traffic Characteristics): Zebra-striped tables for Top 10 IP
 *   Talkers, Top 10 Destination Ports & Services, and Top 10 Directional Flows.
 * - Page 3 (Visualizations): 2x2 grid directly embedding all 4 vector charts
 *   via @c charts.h.
 * - Page 4+ (Detected Anomalies): Color-coded severity badges (CRITICAL red,
 *   WARNING orange, INFO blue), category, subject, and wrapped descriptions
 *   with automatic multi-page pagination. If empty, displays a clean placeholder.
 *
 * Every page includes a uniform header and footer with generation timestamp
 * and page numbering ("Page X of Y").
 *
 * @param cfg        Parsed CLI configuration providing input files and settings (borrowed).
 * @param stats      Finalized traffic statistics context (borrowed).
 * @param anomalies  List of detected network anomalies (borrowed).
 * @param pdf_path   Destination file path for the output PDF (borrowed).
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if any required pointer argument is NULL or invalid,
 *         PCAPSTAT_ERR_NOMEM on memory allocation failure,
 *         PCAPSTAT_ERR_IO if the output file cannot be created or written,
 *         PCAPSTAT_ERR_RENDER on Cairo surface or rendering failure.
 */
int report_generate(const cli_config_t *cfg,
                    const stats_ctx_t *stats,
                    const anomaly_list_t *anomalies,
                    const char *pdf_path);

#endif /* PCAPSTAT_REPORT_H */
