/**
 * @file common.h
 * @brief Shared types, error codes, anomaly thresholds, and helper macros
 *        for the pcapstat project.
 */

#ifndef PCAPSTAT_COMMON_H
#define PCAPSTAT_COMMON_H

#include <stddef.h>
#include <stdint.h>

/** @brief Semantic version string for pcapstat. */
#define PCAPSTAT_VERSION "0.1.0"

/** @brief Maximum path length used throughout the project. */
#define PCAPSTAT_MAX_PATH 4096

/** @brief Maximum number of input files accepted on the CLI. */
#define PCAPSTAT_MAX_INPUT_FILES 256

/**
 * @brief Error codes returned by pcapstat functions.
 *
 * All public functions that can fail return one of these values.
 * Success is always @c PCAPSTAT_OK (0); failures are negative.
 */
enum pcapstat_err {
    PCAPSTAT_OK         =  0, /**< Success. */
    PCAPSTAT_ERR_ARGS   = -1, /**< Invalid or missing CLI arguments. */
    PCAPSTAT_ERR_IO     = -2, /**< File I/O error (open, read, write). */
    PCAPSTAT_ERR_PCAP   = -3, /**< libpcap-specific error. */
    PCAPSTAT_ERR_NOMEM  = -4, /**< Memory allocation failure. */
    PCAPSTAT_ERR_RENDER = -5  /**< Cairo rendering / PDF generation error. */
};

/* -------------------------------------------------------------------
 * Anomaly-detection threshold defaults
 * ------------------------------------------------------------------- */

/** @brief Default minimum unique destination ports to flag a port scan. */
#define DEFAULT_PORTSCAN_THRESHOLD  20

/** @brief Default minimum SYN count before evaluating SYN-flood ratio. */
#define DEFAULT_SYN_FLOOD_MIN       50

/** @brief Default SYN-to-SYN-ACK ratio above which a SYN flood is flagged. */
#define DEFAULT_SYN_RATIO           3.0

/** @brief Default per-flow TCP retransmission percentage threshold. */
#define DEFAULT_RETRANS_PCT         5.0

/** @brief Default RST percentage of TCP traffic to flag an RST spike. */
#define DEFAULT_RST_PCT             10.0

/** @brief Default multiplier of mean UDP pkt/s for burst detection. */
#define DEFAULT_UDP_BURST_MULT      3.0

/** @brief Default minimum absolute UDP packets/s to trigger burst alert. */
#define DEFAULT_UDP_BURST_MIN       100

/**
 * @brief Run-time anomaly-detection thresholds.
 *
 * Shared by @c cli.h (user overrides) and @c anomaly.h (evaluation).
 * Initialize with @ref ANOMALY_THRESHOLDS_DEFAULT.
 */
typedef struct {
    uint32_t portscan_threshold;  /**< Unique dst-port count for port-scan. */
    uint32_t syn_flood_min;       /**< Min SYN packets before ratio check. */
    double   syn_ratio;           /**< SYN / SYN-ACK ratio threshold. */
    double   retrans_pct;         /**< TCP retransmission % threshold. */
    double   rst_pct;             /**< RST % of TCP traffic threshold. */
    double   udp_burst_mult;      /**< UDP burst multiplier of mean. */
    uint32_t udp_burst_min;       /**< Absolute min UDP pkt/s for burst. */
} anomaly_thresholds_t;

/** @brief Compile-time initializer for @ref anomaly_thresholds_t defaults. */
#define ANOMALY_THRESHOLDS_DEFAULT          \
    {                                       \
        .portscan_threshold = DEFAULT_PORTSCAN_THRESHOLD, \
        .syn_flood_min      = DEFAULT_SYN_FLOOD_MIN,      \
        .syn_ratio          = DEFAULT_SYN_RATIO,           \
        .retrans_pct        = DEFAULT_RETRANS_PCT,         \
        .rst_pct            = DEFAULT_RST_PCT,             \
        .udp_burst_mult     = DEFAULT_UDP_BURST_MULT,      \
        .udp_burst_min      = DEFAULT_UDP_BURST_MIN        \
    }

/* -------------------------------------------------------------------
 * Safe helper macros
 * ------------------------------------------------------------------- */

/** @brief Return the minimum of two values (evaluated once each). */
#define PCAPSTAT_MIN(a, b) \
    ({                     \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a < _b ? _a : _b;     \
    })

/** @brief Return the maximum of two values (evaluated once each). */
#define PCAPSTAT_MAX(a, b) \
    ({                     \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a > _b ? _a : _b;     \
    })

/** @brief Number of elements in a statically-sized array. */
#define PCAPSTAT_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif /* PCAPSTAT_COMMON_H */
